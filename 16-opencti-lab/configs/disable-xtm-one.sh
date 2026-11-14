cd /root/opencti/docker
cp docker-compose.yml docker-compose.yml.bak
python3 - << 'PY'
import re
p = 'docker-compose.yml'
targets = {'pgsql-xtm-one', 'xtm-one', 'xtm-one-worker', 'xtm-composer', 'rsa-key-generator'}
out, in_block = [], False
for line in open(p).read().split('\n'):
    m = re.match(r'^  ([a-zA-Z0-9_.-]+):\s*$', line)
    if m:
        in_block = m.group(1) in targets
    elif in_block and line.strip() and not line.startswith('   ') and not line.lstrip().startswith('#'):
        in_block = False
    out.append('#' + line if in_block else line)
open(p, 'w').write('\n'.join(out))
print("done")
PY
sed -i 's|^\( *\)- XTM__XTM_ONE_URL=|\1#- XTM__XTM_ONE_URL=|' docker-compose.yml
