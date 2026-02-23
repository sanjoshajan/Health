def test_minimize():
    from compliance import data_minimize
    p = {'id':'1','name':'A','dob':'2000-01-01','consent':True,'ssn':'X'}
    m = data_minimize(p)
    assert 'ssn' not in m and 'name' in m