import pytest
from backend.app.version_assessment import compare


@pytest.mark.parametrize('eco,version,ranges,expected',[
    ('pip','1.5',['>= 1.0, < 2.0'],'IN_RANGE'),
    ('pip','2.0',['>= 1.0, < 2.0'],'OUT_OF_RANGE'),
    ('pip','2.1',['< 1.0','>= 2.0, < 3.0'],'IN_RANGE'),
    ('pip','2.1',['< 1.0','> 3.0'],'OUT_OF_RANGE'),
    ('pip','2.1',['< 1.0','unrecognized'],'UNKNOWN'),
    ('pip','0.9',['< 1.0','unrecognized'],'IN_RANGE'),
    ('pip','1.0rc1',['< 2.0'],'UNKNOWN'),
    ('pip','1.0+vendor',['< 2.0'],'UNKNOWN'),
    ('npm','1.2.3',['>= 1.2.0, < 2.0.0'],'IN_RANGE'),
    ('npm','2.0.0',['>= 1.2.0, < 2.0.0'],'OUT_OF_RANGE'),
    ('npm','1.2.3',['< 2.0'],'UNKNOWN'),
    ('npm','1.2.3-beta.1',['< 2.0.0'],'UNKNOWN'),
    ('npm','1.2.3',['^1.0.0'],'UNKNOWN'),
    ('npm','01.2.3',['< 2.0.0'],'UNKNOWN'),
    ('maven','1.2.3',['< 2.0.0'],'UNKNOWN'),
    ('pip',None,['< 2.0'],'UNKNOWN'),
    ('pip','1.0',[],'UNKNOWN'),
    ('pip','1.0',[None],'UNKNOWN'),
])
def test_conservative_comparison(eco,version,ranges,expected):
    assert compare(eco,version,None,ranges)['status']==expected


def test_conflicting_component_and_purl_versions_are_unknown():
    assert compare('pip','1.0','2.0',['< 3.0'])['reason']=='version_conflict'
