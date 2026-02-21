# delete_all_projects.py
"""Delete all projects from Dependency Track."""

import requests
from config import get_api_headers, get_dtrack_url

url = f'{get_dtrack_url()}api/v1/project'
headers = get_api_headers()

# Get all projects
all_projects = []
page = 1
page_size = 100

while True:
    params = {'page': page, 'size': page_size}
    response = requests.get(url, headers=headers, params=params)
    projects = response.json()
    if not projects:
        break
    all_projects.extend(projects)
    if len(projects) < page_size:
        break
    page += 1

print(f'Found {len(all_projects)} projects to delete')

# Delete each project
deleted = 0
failed = 0
for project in all_projects:
    uuid = project['uuid']
    name = project['name']
    del_url = f'{get_dtrack_url()}api/v1/project/{uuid}'
    response = requests.delete(del_url, headers=headers)
    if response.status_code in [200, 204]:
        deleted += 1
        if deleted % 50 == 0:
            print(f'  Deleted {deleted}/{len(all_projects)}...')
    else:
        failed += 1
        print(f'  Failed to delete {name}: {response.status_code}')

print(f'\nDeleted: {deleted}')
print(f'Failed: {failed}')
