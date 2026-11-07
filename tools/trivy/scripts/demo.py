"""Exercise actual Trivy finding selection using fictional report rows."""
import json
from pathlib import Path
from security_scan import gate_findings
def demo():
    report={'SchemaVersion':2,'Results':[{'Target':'fixture/package-lock.json','Packages':[{'Name':'example-package','Version':'1.0.0'}],'Vulnerabilities':[
      {'VulnerabilityID':'SYNTHETIC-HIGH','Severity':'HIGH','PkgName':'example-package','InstalledVersion':'1.0.0','FixedVersion':'1.0.1'},
      {'VulnerabilityID':'SYNTHETIC-UNFIXED','Severity':'HIGH','PkgName':'unfixed-package','InstalledVersion':'1.0.0'},
      {'VulnerabilityID':'SYNTHETIC-MEDIUM','Severity':'MEDIUM','PkgName':'example-library','InstalledVersion':'2.0.0','FixedVersion':'2.0.1'}]}]}
    selected=gate_findings(report,'vuln')
    return {'fixture':True,'rawFindingsPreserved':3,'blockingFixableHighCritical':len(selected),'selectedIds':[r['id'] for r in selected],'outcome':'blocked' if selected else 'threshold-passed'}
if __name__=='__main__':print(json.dumps(demo(),indent=2))
