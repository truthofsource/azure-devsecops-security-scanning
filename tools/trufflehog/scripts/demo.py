"""Pass a fictional candidate through the actual private-output parser."""
import json,tempfile
from pathlib import Path
from trufflehog_report import parse_findings,validate_completion
def demo():
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);candidate=root/'candidate.ndjson';completion=root/'completion.ndjson'
        candidate.write_text(json.dumps({'DetectorName':'Test','Raw':'FICTIONAL-NOT-A-CREDENTIAL','Redacted':'DO-NOT-PUBLISH','ExtraData':{'private':'DO-NOT-PUBLISH'},'SourceMetadata':{'Data':{'Git':{'commit':'a'*40,'file':'fixture.txt','line':1}}}})+'\n')
        completion.write_text(json.dumps({'level':'info','msg':'finished scanning','trufflehog_version':'3.99.4','chunks':1,'bytes':128})+'\n')
        validate_completion(completion,'3.99.4');counts=parse_findings(candidate,set())
        assert not any(k in json.dumps(counts) for k in ['FICTIONAL','DO-NOT-PUBLISH','Raw','Redacted','ExtraData'])
        return {'fixture':True,**counts,'completed':True,'secretValuesPublished':False,'providerVerification':False}
if __name__=='__main__':print(json.dumps(demo(),indent=2))
