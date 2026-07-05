import os
import uuid
import time
import grpc
import json
import redis
import requests
import threading
import signal
import sys
import traceback
from dataclasses import dataclass
from typing import Callable, Optional, Dict, Any

# Immediate feedback on module load
print("[*] xbin SDK loading...")

try:
    from xbin_orchestrator import orchestrator_pb2
    from xbin_orchestrator import orchestrator_pb2_grpc
except Exception as e:
    print(f"[*] Local stub fallback (Error: {e})")
    import sys
    # Add both the parent and the specific directory to path to satisfy gRPC's flat imports
    target_dir = os.path.join(os.path.dirname(__file__), "..", "xbin_orchestrator")
    sys.path.append(os.path.abspath(target_dir))
    import orchestrator_pb2
    import orchestrator_pb2_grpc

@dataclass
class Match:
    symbol: str
    confidence: float

@dataclass
class TaskContext:
    address: int
    raw_bytes: bytes

class Worker:
    def __init__(self, name: str, category: str, version: str, is_validator: bool = False, is_ranker: bool = False,
                 display_name: str = "", description: str = ""):
        self.name = name
        self.category = category
        self.version = version
        self.is_validator = is_validator
        self.is_ranker = is_ranker
        # Human-friendly label + blurb shown in the dashboard. display_name falls
        # back to the technical backend name when not set.
        self.display_name = display_name or name
        self.description = description
        self.worker_id = f"{name}-{uuid.uuid4().hex[:8]}"
        
        self.on_binary_handler = None
        self.on_update_handler = None
        
        self.orchestrator_addr = os.getenv("XBIN_ORCHESTRATOR", "localhost:50051")
        self.redis_host = os.getenv("REDIS_HOST", "localhost")
        self.rest_url = f"http://{self.orchestrator_addr.split(':')[0]}:8000"
        
        type_str = "[VALIDATOR]" if is_validator else "[RANKER]" if is_ranker else ""
        print(f"[*] Initializing Worker: {self.name} ({self.category}) {type_str}")
        
        try:
            self._channel = grpc.insecure_channel(self.orchestrator_addr)
            self._stub = orchestrator_pb2_grpc.OrchestratorServiceStub(self._channel)
            self._redis = redis.Redis(host=self.redis_host, port=6379, decode_responses=True)
            self._is_running = True
            
            signal.signal(signal.SIGTERM, self._handle_exit)
            signal.signal(signal.SIGINT, self._handle_exit)
        except Exception as e:
            print(f"[ERROR] Worker initialization failed: {e}")
            traceback.print_exc()

    def _handle_exit(self, signum, frame):
        print(f"[*] Shutdown signal {signum} received. Exiting...")
        self._is_running = False
        try:
            self._stub.Heartbeat(orchestrator_pb2.HeartbeatRequest(
                worker_id=self.worker_id, status_message="SHUTDOWN"
            ))
        except: pass
        sys.exit(0)

    def _heartbeat_loop(self):
        while self._is_running:
            try:
                self._stub.Heartbeat(orchestrator_pb2.HeartbeatRequest(
                    worker_id=self.worker_id, status_message="Online & Ready"
                ))
            except: pass
            time.sleep(5)

    def register(self):
        print(f"[*] Connecting to {self.orchestrator_addr}...")
        try:
            resp = self._stub.RegisterWorker(orchestrator_pb2.RegisterRequest(
                worker_id=self.worker_id, backend_name=self.name,
                analysis_type=self.category, is_validator=self.is_validator,
                is_ranker=self.is_ranker, display_name=self.display_name,
                description=self.description
            ))
            if resp.success:
                print(f"[+] READY: Registered with ID {self.worker_id}")
                threading.Thread(target=self._heartbeat_loop, daemon=True).start()
                return True
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            return False

    def post_result(self, item_key: str, data: Any, confidence: float, category: Optional[str] = None):
        # `category` defaults to the worker's own category, but a worker may post
        # to a different blackboard (e.g. bind_se posts semantics to
        # equation_recovery and an identity match to signature_matching).
        target_cat = category or self.category
        try:
            self._stub.PostResult(orchestrator_pb2.PostResultRequest(
                analysis_type=target_cat, item_key=item_key,
                result_data=json.dumps(data), confidence=confidence, backend_name=self.name
            ))
            print(f"[>] Result posted for {item_key} in {target_cat} (Conf: {confidence})")
        except Exception as e:
            print(f"[ERROR] Post failed for {item_key}: {e}")

    def post_validation(self, item_key: str, target_id: str = "TOP", confidence: float = 1.0):
        """Vouch for an existing hypothesis instead of posting new data."""
        try:
            self._stub.PostResult(orchestrator_pb2.PostResultRequest(
                analysis_type=self.category, item_key=item_key,
                result_data="", confidence=confidence, backend_name=self.name,
                validation_target_id=target_id
            ))
            print(f"[V] Validation posted for {item_key} -> {target_id} (Conf: {confidence})")
        except Exception as e:
            print(f"[ERROR] Validation failed for {item_key}: {e}")

    def update_rank(self, item_key: str, target_id: str, new_score: float):
        """Specifically for Rankers: Update the score of a hypothesis."""
        try:
            self._stub.UpdateRank(orchestrator_pb2.UpdateRankRequest(
                analysis_type=self.category, item_key=item_key,
                target_hypothesis_id=target_id, new_score=new_score,
                backend_name=self.name
            ))
            print(f"[R] Rank updated for {item_key} (ID: {target_id}) -> {new_score}")
        except Exception as e:
            print(f"[ERROR] Rank update failed for {item_key}: {e}")

    def get_analysis(self, category: str, item_key: Optional[str] = None):
        url = f"{self.rest_url}/api/v1/blackboard/{category}"
        if item_key: url += f"/{item_key}"
        try:
            resp = requests.get(url, timeout=5)
            return resp.json()
        except: return None

    def run(self):
        print(f"[*] xbin Worker {self.name} starting event loop...")
        if not self.register(): 
            print("[CRITICAL] Could not register. Stopping.")
            return
        
        try:
            pubsub = self._redis.pubsub()
            pubsub.subscribe("xbin:events")
            print(f"[*] Subscribed to global blackboard stream.")
            
            for message in pubsub.listen():
                if not self._is_running: break
                if message["type"] == "message":
                    event = json.loads(message["data"])
                    
                    if event["type"] == "NEW_BINARY" and self.on_binary_handler:
                        print(f"[*] Event: New Binary {event['filename']}")
                        self.on_binary_handler(event["path"], event.get("requested_analyses", []))
                        
                    elif event["type"] == "BLACKBOARD_UPDATE" and self.on_update_handler:
                        self.on_update_handler(
                            event["analysis_type"], 
                            event["item_key"], 
                            event["new_hypothesis"], 
                            event["top_hypothesis"]
                        )
        except Exception as e:
            print(f"[CRITICAL] Event loop crash: {e}")
            traceback.print_exc()

_current_worker: Optional[Worker] = None

def plugin(name: str, category: str, version: str = "1.0", is_validator: bool = False, is_ranker: bool = False,
           display_name: str = "", description: str = ""):
    global _current_worker
    _current_worker = Worker(name, category, version, is_validator, is_ranker, display_name, description)
    def decorator(cls):
        try:
            instance = cls()
            if hasattr(instance, 'on_new_binary'): _current_worker.on_binary_handler = instance.on_new_binary
            if hasattr(instance, 'on_update'): _current_worker.on_update_handler = instance.on_update
            print(f"[+] Plugin decorated: {cls.__name__}")
        except Exception as e:
            print(f"[ERROR] Failed to instantiate plugin class: {e}")
            traceback.print_exc()
        return cls
    return decorator

def start_worker():
    if _current_worker:
        try:
            _current_worker.run()
        except Exception as e:
            print(f"[CRITICAL] Worker failed: {e}")
            traceback.print_exc()
    else:
        print("[ERROR] No plugin defined. Use @xbin.plugin.")

def post_result(item_key: str, data: Any, confidence: float, category: Optional[str] = None):
    if _current_worker:
        _current_worker.post_result(item_key, data, confidence, category)
    else:
        print("[ERROR] No active worker. Call @xbin.plugin first.")

def post_validation(item_key: str, target_id: str = "TOP", confidence: float = 1.0):
    if _current_worker:
        _current_worker.post_validation(item_key, target_id, confidence)
    else:
        print("[ERROR] No active worker. Call @xbin.plugin first.")

def update_rank(item_key: str, target_id: str, new_score: float):
    if _current_worker:
        _current_worker.update_rank(item_key, target_id, new_score)
    else:
        print("[ERROR] No active worker. Call @xbin.plugin first.")

def get_analysis(category: str, item_key: Optional[str] = None):
    if _current_worker:
        return _current_worker.get_analysis(category, item_key)
    else:
        print("[ERROR] No active worker. Call @xbin.plugin first.")
        return None
