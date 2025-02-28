def is_ssrf_vulnerable(response, test_url):
    # Check for SSRF indicators in response
    return any(indicator in response.text.lower() for indicator in [
        'private network',
        'internal server',
        'connection refused',
        'network unreachable'
    ])

def scan_for_ssrf(url, method='GET', headers=None, params=None, data=None):
    vulnerabilities = []
    test_urls = [
        'http://localhost',
        'http://127.0.0.1',
        'http://169.254.169.254',  # AWS metadata
        'http://192.168.0.1'
    ]
    
    vectors = [
        {'params': params, 'data': data}
    ]
    
    for test_url in test_urls:
        for vector in vectors:
            try:
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    params=vector['params'],
                    data=vector['data'],
                    timeout=10,
                    allow_redirects=False
                )
                
                if is_ssrf_vulnerable(response, test_url):
                    vulnerabilities.append({
                        'type': 'SSRF',
                        'severity': 'HIGH',
                        'detail': f'Potential SSRF vulnerability with {test_url}',
                        'evidence': {
                            'url': url,
                            'method': method,
                            'request': {
                                'headers': dict(headers),
                                'params': vector['params'],
                                'body': vector['data']
                            },
                            'response': {
                                'headers': dict(response.headers),
                                'status_code': response.status_code,
                                'body': response.text[:500]
                            },
                            'test_url': test_url
                        }
                    })
            except Exception as e:
                print(f'Error testing {test_url}: {str(e)}')
                
    return vulnerabilities