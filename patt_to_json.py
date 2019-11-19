import json

filepath = 'patterns.txt'
vulnerabilities = []
with open(filepath) as fp:
    temp = fp.read().splitlines()

for i in range(0, len(temp), 5):
    data = {}
    data["vulnerability"] = temp[i]
    data["sources"]       = temp[i+1].split(', ')
    data["sanitizers"]    = temp[i+2].split(', ')
    data["sinks"]         = temp[i+3].split(', ')
    vulnerabilities.append(json.dumps(data))

print(vulnerabilities)

