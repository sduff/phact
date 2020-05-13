#!/usr/local/bin/python

import re, csv, sys

re_title = re.compile("<h4.*<strong>(?P<title>.*)</strong>.*>")
re_desc = re.compile("content-row-description\">(?P<desc>.*)</div>")

print """# PhApp

Generate a list of all Phantom Apps (https://my.phantom.us/4.8/apps/)

---

"""

with open("phantom_apps_4.8") as f:
    for l in f:
        l = l.strip()

        m_title = re_title.search(l)
        m_desc = re_desc.search(l)

        if m_title:
            app = m_title.group("title")
            print "\n## ", app

        if m_desc:
            desc = m_desc.group("desc")
            print desc
