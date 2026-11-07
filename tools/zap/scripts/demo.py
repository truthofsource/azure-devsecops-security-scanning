"""Exercise the actual ten-GET evaluator with a fictional in-memory probe."""
import json
from zap_role_matrix import evaluate,SETTINGS
from zap_authenticated import alert_counts
def demo():
    ids={'admin':'a'*8+'-aaaa-aaaa-aaaa-'+'a'*12,'caregiver':'b'*8+'-bbbb-bbbb-bbbb-'+'b'*12}
    def probe(path,token):
        if path=='/api/health':return 200,'{}'
        if token is None:return 401,'{}'
        if path=='/api/me':return 200,json.dumps({'objectId':ids[token],'roles':['Workforce.Admin' if token=='admin' else 'Workforce.Caregiver']})
        return (400 if path==SETTINGS else 503,'{}') if token=='admin' else (403,'{}')
    rows=evaluate(probe,'admin','caregiver',ids['admin'],ids['caregiver'])
    return {'fixture':True,'requests':rows,'requestCount':len(rows),'bodyOrTokenPublished':False,'activeScan':False,'illustrativeAlertSummary':alert_counts([{'pluginId':'10038','risk':'Informational','url':'FICTIONAL-PRIVATE-URL'}])}
if __name__=='__main__':print(json.dumps(demo(),indent=2))
