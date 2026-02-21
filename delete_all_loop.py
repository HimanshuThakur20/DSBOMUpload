# delete_all_loop.py
"""Delete all projects from Dependency Track - runs until all deleted."""

import requests
import time
from config import get_api_headers, get_dtrack_url

url = f'{get_dtrack_url()}api/v1/project'
headers = get_api_headers()

total_deleted = 0
iteration = 0

while True:
    iteration += 1
    
    # Get projects (just first page)
    response = requests.get(url, headers=headers, params={'size': 100})
    projects = response.json()
    
    if not projects:
        print(f'\nAll projects deleted! Total: {total_deleted}')
        break
    
    print(f'Iteration {iteration}: Found {len(projects)} projects')
    
    # Delete each project
    deleted = 0
    for project in projects:
        uuid = project['uuid']
        del_url = f'{get_dtrack_url()}api/v1/project/{uuid}'
        response = requests.delete(del_url, headers=headers)
        if response.status_code in [200, 204]:
            deleted += 1
    
    total_deleted += deleted
    print(f'  Deleted {deleted} in this iteration (Total: {total_deleted})')
    
    # Small pause to avoid overwhelming the server
    time.sleep(0.5)
