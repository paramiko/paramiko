from collections import namedtuple
from datetime import datetime
import time
import email.utils

from sphinx.util.compat import Directive
from docutils import nodes


class BlogDateDirective(Directive):
    """
    Used to parse/attach date info to blog post documents.

    No nodes generated, since none are needed.
    """
    has_content = True

    def run(self):
        # Tag parent document with parsed date value.
        self.state.document.blog_date = datetime.strptime(
            self.content[0], "%Y-%m-%d"
        )
        # Don't actually insert any nodes, we're already done.
        return []

class blog_post_list(nodes.General, nodes.Element):
    pass

class BlogPostListDirective(Directive):
    """
    Simply spits out a 'blog_post_list' temporary node for replacement.

    Gets replaced at doctree-resolved time - only then will all blog post
    documents be written out (& their date directives executed).
    """
    def run(self):
        return [blog_post_list('')]


Post = namedtuple('Post', 'name doc title date opener')

def get_posts(app):
    # Obtain blog posts
    post_names = filter(lambda x: x.startswith('blog/'), app.env.found_docs)
    posts = map(lambda x: (x, app.env.get_doctree(x)), post_names)
    # Obtain common data used for list page & RSS
    data = []
    for post, doc in sorted(posts, key=lambda x: x[1].blog_date, reverse=True):
        # Welp. No "nice" way to get post title. Thanks Sphinx.
        title = doc[0][0][0]
        # Date. This may or may not end up reflecting the required
        # *input* format, but doing it here gives us flexibility.
        date = doc.blog_date
        # 1st paragraph as opener. TODO: allow a role or something marking
        # where to actually pull from?
        opener = doc.traverse(nodes.paragraph)[0]
        data.append(Post(post, doc, title, date, opener))
    return data

def replace_blog_post_lists(app, doctree, fromdocname):
    """
    Replace blog_post_list nodes with ordered list-o-links to posts.
    """
    # Obtain blog posts
    post_names = filter(lambda x: x.startswith('blog/'), app.env.found_docs)
    posts = map(lambda x: (x, app.env.get_doctree(x)), post_names)
    # Build "list" of links/etc
    post_links = []
    for post, doc, title, date, opener in get_posts(app):
        # Link itself
        uri = app.builder.get_relative_uri(fromdocname, post)
        link = nodes.reference('', '', refdocname=post, refuri=uri)
        # Title, bolded. TODO: use 'topic' or something maybe?
        link.append(nodes.strong('', title))
        date = date.strftime("%Y-%m-%d")
        # Meh @ not having great docutils nodes which map to this.
        html = '<div class="timestamp"><span>%s</span></div>' % date
        timestamp = nodes.raw(text=html, format='html')
        # NOTE: may group these within another element later if styling
        # necessitates it
        group = [timestamp, nodes.paragraph('', '', link), opener]
        post_links.extend(group)

    # Replace temp node(s) w/ expanded list-o-links
    for node in doctree.traverse(blog_post_list):
        node.replace_self(post_links)

def rss_timestamp(timestamp):
    # Use horribly inappropriate module for its magical daylight-savings-aware
    # timezone madness. Props to Tinkerer for the idea.
    return email.utils.formatdate(
        time.mktime(timestamp.timetuple()),
        localtime=True
    )

def generate_rss(app):
    # Meh at having to run this subroutine like 3x per build. Not worth trying
    # to be clever for now tho.
    posts_ = get_posts(app)
    # LOL URLs
    root = app.config.rss_link
    if not root.endswith('/'):
        root += '/'
    # Oh boy
    posts = [
        (
            root + app.builder.get_target_uri(x.name),
            x.title,
            str(x.opener[0]), # Grab inner text element from paragraph
            rss_timestamp(x.date),
        )
        for x in posts_
    ]
    location = 'blog/rss.xml'
    context = {
        'title': app.config.project,
        'link': root,
        'atom': root + location,
        'description': app.config.rss_description,
        # 'posts' is sorted by date already
        'date': rss_timestamp(posts_[0].date),
        'posts': posts,
    }
    yield (location, context, 'rss.xml')

def setup(app):
    # Link in RSS feed back to main website, e.g. 'http://paramiko.org'
    app.add_config_value('rss_link', None, '')
    # Ditto for RSS description field
    app.add_config_value('rss_description', None, '')
    # Interprets date metadata in blog post documents
    app.add_directive('date', BlogDateDirective)
    # Inserts blog post list node (in e.g. a listing page) for replacement
    # below
    app.add_node(blog_post_list)
    app.add_directive('blog-posts', BlogPostListDirective)
    # Performs abovementioned replacement
    app.connect('doctree-resolved', replace_blog_post_lists)
    # Generates RSS page from whole cloth at page generation step
    app.connect('html-collect-pages', generate_rss)
