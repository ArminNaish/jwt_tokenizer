import pytest

from .. import jwt


def test_should_sign_token_with_hs256():
    payload = {'foo': 'bar'}
    token = jwt.sign(payload, 'the_secret_key', options={
        'algorithm': 'HS256',
        'expires-in': 1869339578,
        'issued-at': 1569309578,
        'jwt-id': 'a82edf05-e246-4bfc-bd51-50e6686958f7',
        'not-before': 1869309578
    })
    assert token == 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4NjkzMzk1NzgsImZvbyI6ImJhciIsImlhdCI6MTU2OTMwOTU3OCwianRpIjoiYTgyZWRmMDUtZTI0Ni00YmZjLWJkNTEtNTBlNjY4Njk1OGY3IiwibmJmIjoxODY5MzA5NTc4fQ.dB5ORHmAnrwdMGHfhVH4MAz32MmV9B97HmFK3NR1hkI'


def test_should_verify_token_wiht_hs256():
    signed_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4NjkzMzk1NzgsImZvbyI6ImJhciIsImlhdCI6MTU2OTMwOTU3OCwianRpIjoiYTgyZWRmMDUtZTI0Ni00YmZjLWJkNTEtNTBlNjY4Njk1OGY3IiwibmJmIjoxNTY5MzA5NTc4fQ.Mcb6sIHpqE5QiqrhwS0h3MgXaHlVIMpctkM2JikQy_A'
    payload = jwt.verify(signed_token, 'the_secret_key')
    assert payload == {'exp':1869339578,'foo':'bar','iat': 1569309578,'jti':'a82edf05-e246-4bfc-bd51-50e6686958f7','nbf':1569309578}


def test_should_sign_token_with_rsa():
    private_key = '''-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhvaQ4uBXYcK02
OYiEawraekmPxQqa/3mHofahDlV6wXf/bm7rP5tZkJf7s3OwZAPUOrPvYPJ2IaGk
MeOuPe+9mG8T6Yo9EIpXvVmDif6DwhkOFQV5MAGTs+y4eoWCeK4A811pnJ19FVc8
PhI4wn/cmDvzu2VS/+tKngvUdvfQQW3te780BvdLC/12/KWTqbKF2CnUbVTjbvYz
JAEzk7bEHKYaHqieVwD+tKC1fbLuJGBPRGSQg0LWmHXaAMDcurrSOKe5oy2Z9s84
v89urADy9KDuEw0TYh+sfzK7UM1GGc5mtC2JpJIa/aGYuFHsWzdwF36M8xsWbAIO
eyr4DEJBAgMBAAECggEAWe2uilnrefoJRtzModPy0u58d6XLf8veokXHdom7S9fe
8gcQcO85+Ag+Q6tNnyt4ywdHv0kjziO/vSWSyksqQqGDPq9+vqzkL+fizSAgIGUm
jhGZyJlzR2AaIbPNlBh3WTGaOQSHSNlDk2A26h2xyjNrTsGMr+/70BH+LHnoZzGp
4j7720F1qTCax0J3dZemSQb5C2GrjG6+E+fyHOH9tACpS394Q9Azo3CZxq3DN8LY
+xZe/n7GjxbCzqfqTZwd2GCwb1O/ptkSJFeBrJfogQ3p7blsC9dntFgeeuzs0GeW
ViLCdV8TDQF39TjFBthCjCKoUVFrS7K3UYSgke3AsQKBgQD6jL4Wr7zE3mILx4n2
E3HEsUJZAEvWijBF8eoesKUZokTiFVjk3gKAIG186KaR0aQY1uJksUmSBFmGQOz0
uDqjwvyza8GtPJHDiCB1BXoS3GqX/N3h7HY58d3zx1F4tkUR9xV9PLgHIkApmpGf
zltr8LZODNEdg35rWOuYZagZowKBgQDmpr452bOntehipSjiBI+rTcSWP2AkHjuk
0LfsbSm8GQizn1Z0r/hWeR9vgU3Lq+ohmjLBlFVzB2DYFxvyNj56Pw9P4v/8l/we
ME/o0uvUgY0uwWceoL/bGjcBgIjYGS5yzMzEscmDhMuyXhSNpRDrz/fp+us7JBto
x0AWw1s6ywKBgD8JtDXvB1adARwnmy1/nOs5EhFkgrA62oRuplIMba2yZxRe/Juw
w/5KqmF4A5jCnz/kqNdex7zmPUQLB9NWmuJjB8N4xCT7DU2d7VSkCR+/t04AQC88
mE5h7U8NghEWAvDPMufso/yfgHc3PZZwjA3vZV7j2KVNVTxbBgO06ANzAoGBAJIZ
4vswDF3am1YI+kmYzAydmT327QZT5EH1N9vaFgqg7OMithf581uLI79073to7UjV
rPrz4+CWNuEKWlhlxdOXqDJZPv+YoknZHnUDTgDxAyYvugsrlfvKsjcQXR5NbR+o
3LhnSZc2gfT9JRXIDlzhAk/C8kgnCfmn5M/GdT5bAoGAOJ7RXU7L80VdZ4q603y9
nOk2P302kwY27+i4aREnzSkOxbdJfyE8hoKc7F9oAQrTnc6Yv978eLqVQtxWGuIx
UMy/8nQimp4WYPeZRvpiUvEH4MCc2f6Lc2+hqNv535RbOCFlV3b4wnlSVEH4q6QE
c8cxpG3/CylnU6Iqn9EcXyg=
-----END PRIVATE KEY-----'''
    payload = {'foo': 'bar'}
    token = jwt.sign(payload, secret=private_key, options={
        'algorithm': 'RS256',
        'expires-in': 1869339578,
        'issued-at': 1569309578,
        'jwt-id': 'a82edf05-e246-4bfc-bd51-50e6686958f7',
        'not-before': 1869309578
    })
    assert token == 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4NjkzMzk1NzgsImZvbyI6ImJhciIsImlhdCI6MTU2OTMwOTU3OCwianRpIjoiYTgyZWRmMDUtZTI0Ni00YmZjLWJkNTEtNTBlNjY4Njk1OGY3IiwibmJmIjoxODY5MzA5NTc4fQ.ok5XbDJLV5J1X1oLVXLTeBkQ6p8BnG6-JV1wB8Zp37kpWvXmqG41JJcNurJY5jzlLWJHK4R8zoJxaVAR3lwS5n4zX77auSQLh3a27ZhVWX0c0pqiD0xXvlxC3mfNhMRz9rxBtq2iOOxKsrOzUDgFjnBTnPAttO3b_hdMGuIytVk9u7yoi2DhSzeP68Kh50n0t6_LWhsTIA2KH9G0hiwh3GmxUCrALo-08OyR0fY0FuG0VX2eOZC_g5CrgEXn-KPNyGgao0rh5I4tsKU3H2HUbsFndW32wz7pADDW39-uVXCsn5RlfEpZ_yQO4-PCE5R1-xe1EjIgtjpW2BBsX_DDTA'


def test_should_verify_token_with_rsa():
    public_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4b2kOLgV2HCtNjmIhGsK
2npJj8UKmv95h6H2oQ5VesF3/25u6z+bWZCX+7NzsGQD1Dqz72DydiGhpDHjrj3v
vZhvE+mKPRCKV71Zg4n+g8IZDhUFeTABk7PsuHqFgniuAPNdaZydfRVXPD4SOMJ/
3Jg787tlUv/rSp4L1Hb30EFt7Xu/NAb3Swv9dvylk6myhdgp1G1U4272MyQBM5O2
xBymGh6onlcA/rSgtX2y7iRgT0RkkINC1ph12gDA3Lq60jinuaMtmfbPOL/PbqwA
8vSg7hMNE2IfrH8yu1DNRhnOZrQtiaSSGv2hmLhR7Fs3cBd+jPMbFmwCDnsq+AxC
QQIDAQAB
-----END PUBLIC KEY-----'''
    signed_token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4NjkzMzk1NzgsImZvbyI6ImJhciIsImlhdCI6MTU2OTMwOTU3OCwianRpIjoiYTgyZWRmMDUtZTI0Ni00YmZjLWJkNTEtNTBlNjY4Njk1OGY3IiwibmJmIjoxNTY5MzA5NTc4fQ.KAxSVWQ9pL679AKkSamAzHBkmF-x0uftJOyaEJMy0GazzVmzlYbGstEiLJBsy2MNckHZxjPEqkAoPh0nnnrwFF5X4U1v7fPYhTaiacdfLGYuPQQfA5G8vZWnYwR4q62GA-8ZvG_sq8FymHAi3HnrH3kCBWEPPRqLmgGu7Gf5XNU9-cCJ-aAROvrDizi3EJpPar33ef1DcyhMEzdxsJ4euGJNG4dGI8Y1avAauZ67QMpaH12opTonLMEjUbV04qcXW2Jo68ET26xmW-nIyo___RiKsUUVEN_mWtxf6Ytl3Syo79Mk9q7U1qRP_cpPCWZBUmcJNLJ2Bifju-9w4aaZyw'
    payload = jwt.verify(signed_token, secret=public_key)
    assert payload == {'exp':1869339578,'foo':'bar','iat': 1569309578,'jti':'a82edf05-e246-4bfc-bd51-50e6686958f7','nbf':1569309578}



