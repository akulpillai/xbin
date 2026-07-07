import time
import json
from xbin.sdk import Worker
import threading

def wait_for_key(redis_client, key, timeout=2.0):
    start = time.time()
    while time.time() - start < timeout:
        val = redis_client.get(key)
        if val:
            return json.loads(val)
        time.sleep(0.1)
    return None

def test_analyzer_submission(clean_redis):
    cat = 'signature_matching'
    item = '0x1000'
    
    analyzer = Worker(name='test_analyzer', category=cat, version='1.0')
    assert analyzer.register() is True
    
    analyzer.post_result(item_key=item, data={'size': 42}, confidence=1.0)
    
    state = wait_for_key(clean_redis, f'xbin:bb:{cat}:{item}')
    assert state is not None, "Data was not written to Redis in time"
    assert state['status'] == 'RESOLVED'
    assert len(state['hypotheses']) == 1
    assert state['hypotheses'][0]['data']['size'] == 42
    assert state['hypotheses'][0]['score'] == 0.5  # 1.0 conf * 0.5 default weight

def test_validator_vouching(clean_redis):
    cat = 'signature_matching'
    item = '0x1001'
    
    # 1. Setup Analyzer
    analyzer = Worker(name='test_analyzer', category=cat, version='1.0')
    analyzer.register()
    analyzer.post_result(item_key=item, data={'size': 42}, confidence=1.0)
    
    # 2. Setup Validator
    validator = Worker(name='test_validator', category=cat, version='1.0', is_validator=True)
    assert validator.register() is True
    
    # Wait for initial result
    wait_for_key(clean_redis, f'xbin:bb:{cat}:{item}')
    
    # 3. Vouch
    validator.post_validation(item_key=item, target_id="TOP", confidence=1.0)
    time.sleep(0.5) # Give vouch time to process
    
    state = json.loads(clean_redis.get(f'xbin:bb:{cat}:{item}'))
    assert len(state['hypotheses'][0].get('validators', [])) == 1
    assert 'test_validator' in state['hypotheses'][0]['validators']
    assert state['hypotheses'][0]['score'] == 1.0 # 0.5 initial + 0.5 boost from validator

def test_ranker_update(clean_redis):
    cat = 'signature_matching'
    item = '0x1002'
    
    # 1. Submit initial result
    analyzer = Worker(name='test_analyzer', category=cat, version='1.0')
    analyzer.register()
    analyzer.post_result(item_key=item, data={'size': 42}, confidence=1.0)
    
    state = wait_for_key(clean_redis, f'xbin:bb:{cat}:{item}')
    hyp_id = state['hypotheses'][0]['id']
    
    # 2. Setup Ranker
    ranker = Worker(name='test_ranker', category=cat, version='1.0', is_ranker=True)
    assert ranker.register() is True
    
    # 3. Use Ranker to override the score
    ranker.update_rank(item_key=item, target_id=hyp_id, new_score=99.9)
    time.sleep(0.5) # Give rank update time to process
    
    # Verify score was updated
    state = json.loads(clean_redis.get(f'xbin:bb:{cat}:{item}'))
    assert state['hypotheses'][0]['score'] == 99.9
