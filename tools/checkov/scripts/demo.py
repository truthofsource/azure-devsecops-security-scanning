"""Use the actual report validator on a fictional advisory failure."""
import json
from security_checkov import validate_report
def demo():
    data={'check_type':'terraform','summary':{'passed':1,'failed':1,'skipped':0,'parsing_errors':0,'resource_count':1,'checkov_version':'3.3.26'},'results':{'passed_checks':[{'check_id':'CKV_TEST_PASS','resource':'azurerm_storage_account.example','file_path':'/fixture/main.tf'}],'failed_checks':[{'check_id':'CKV_TEST_FAIL','resource':'azurerm_storage_account.example','file_path':'/fixture/main.tf'}],'skipped_checks':[],'parsing_errors':[]}}
    counts=validate_report(data,'3.3.26')
    return {'fixture':True,'completed':True,'securityGate':False,'mode':'advisory-baseline',**counts,'interpretation':'Complete scan with an unresolved finding; not deployment clearance'}
if __name__=='__main__':print(json.dumps(demo(),indent=2))
