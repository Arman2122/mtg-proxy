# The wiki, in the repository

These files are the source of <https://github.com/Arman2122/mtg-proxy/wiki>.

They live here as well as there for two reasons. A wiki has no pull requests and
no review, so a correction to the documentation cannot be proposed the way a
correction to the code can — here it can. And a wiki is a separate git repository
that is easy to forget when the thing it documents changes; here it sits beside
the code it describes, and a change that makes a page wrong shows up in the same
diff.

`publish.sh` copies these to the wiki repository and pushes. The wiki is the copy
people read; this is the copy people change.

## Publishing

GitHub creates a wiki's git repository the first time a page is saved through the
web interface, and not before — there is no API for it. So the very first publish
needs one manual step:

1. Open <https://github.com/Arman2122/mtg-proxy/wiki>
2. Click **Create the first page**, then **Save page**. The content does not
   matter; `publish.sh` overwrites it.

After that:

```bash
./docs/wiki/publish.sh
```

Every later publish needs nothing manual.

## Page names

A file's name is its URL. `WEB-Proxy-Setup.md` becomes
`.../wiki/WEB-Proxy-Setup`, and `[[WEB-Proxy-Setup]]` in any page links to it.
Renaming a file breaks every link to it from outside the wiki, so treat these
names the way you would treat a URL, because that is what they are.

`Home.md` is the landing page. `_Sidebar.md`, if present, is the navigation shown
beside every page.
