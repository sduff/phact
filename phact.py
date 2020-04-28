#!/usr/local/bin/python

import re, csv, sys

re_title = re.compile("<h4.*<strong>(?P<title>.*)</strong>.*>")
re_act = re.compile("<li><strong>(?P<action>.*)</strong>\s*-?\s*(?P<action_diz>[^<]*)</li>")

app = ""
actions = {}

with open("phantom_apps_4.8") as f:
    for l in f:
        l = l.strip()

        m_title = re_title.search(l)
        m_act = re_act.search(l)

        if m_title:
            app = m_title.group("title")

        if m_act:
            action = m_act.group("action")
            act_diz = m_act.group("action_diz")

            if action not in actions:
                actions[action] = {}

            if act_diz not in actions[action]:
                actions[action][act_diz] = []

            actions[action][act_diz].append(app)


print """# PhAct

Generate a list of all actions provided by Phantom Apps (https://my.phantom.us/4.8/apps/)

---

"""

for action, data in sorted(actions.items()):
    diz_count = len(data)
    apps = 0
    for d in data:
        apps = apps + len(data[d])
    print ("## %s"%action)
    print ("_%s unique descriptions / Provided by %s apps_\n"%(diz_count,apps))
    for d in sorted(data):
        print ("* %s"%d)
        for a in  data[d]:
            print ("  * %s"%a)
    print ("\n\n")
