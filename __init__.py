from CTFd.plugins.challenges import BaseChallenge
from CTFd.utils.modes import TEAMS_MODE, get_mode_as_word
from CTFd.utils.decorators import admins_only
from CTFd.utils import get_config, set_config
from CTFd.cache import clear_config
from flask import url_for, Blueprint, render_template, redirect, request, session, abort
from functools import wraps
import requests

class BaseNotifier(object):
    def is_configured(self):
        return bool(self.get_webhook_url())
    def get_webhook_url(self):
        return get_config('notifier_webhook_url')
    def notify_solve(self, solver_name, solver_url, challenge_name, challenge_url):
        pass
    def notify_message(self, title, content):
        pass

class SlackNotifier(BaseNotifier):
    def notify_solve(self, solver_name, solver_url, challenge_name, challenge_url):
        plain_msg = '{solver_name} solved {challenge_name}'.format(
            solver_name=solver_name,
            challenge_name=challenge_name,
        )
        markdown_msg = '<{solver_url}|{solver_name}> solved <{challenge_url}|{challenge_name}>'.format(
            solver_name=solver_name,
            solver_url=solver_url,
            challenge_name=challenge_name,
            challenge_url=challenge_url,
        )

        requests.post(self.get_webhook_url(), json={
            'text': plain_msg,
            'blocks': [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": markdown_msg
                    }
                },
            ]
        })

    def notify_message(self, title, content):
        requests.post(self.get_webhook_url(), json={
            'text': content,
            'blocks': [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": title
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": content
                    }
                },
            ]
        })

class DiscordNotifier(BaseNotifier):
    def notify_solve(self, solver_name, solver_url, challenge_name, challenge_url):
        markdown_msg = '[{solver_name}]({solver_url}) solved [{challenge_name}]({challenge_url})'.format(
            solver_name=solver_name,
            solver_url=solver_url,
            challenge_name=challenge_name,
            challenge_url=challenge_url,
        )

        requests.post(self.get_webhook_url(), json={
            'embeds': [{
                'description': markdown_msg,
            }]
        })

    def notify_message(self, title, content):
        requests.post(self.get_webhook_url(), json={
            'embeds': [{
                'title': title,
                'description': content,
            }]
        })

"""
Global dictionary used to hold all the supported chat services. To add support for a new chat service, create a plugin and insert
your BaseNotifier subclass instance into this dictionary to register it.
"""
NOTIFIER_CLASSES = {"slack": SlackNotifier(), "discord": DiscordNotifier()}

def get_configured_notifier():
    notifier_type = get_config('notifier_type')
    if not notifier_type:
        return None
    notifier = NOTIFIER_CLASSES[notifier_type]
    if not notifier.is_configured():
        return None
    return notifier

def load(app):
    admin_chat_notifier = Blueprint('admin_chat_notifier', __name__, template_folder='templates')

    @admin_chat_notifier.route('/admin/chat_notifier', methods=['GET', 'POST'])
    @admins_only
    def admin_config_chat_notifier():
        clear_config()

        if request.method == "POST":
            if request.form['notifier_type'] and request.form['notifier_type'] not in NOTIFIER_CLASSES.keys():
                abort(400)
            set_config('notifier_type', request.form['notifier_type'])
            set_config('notifier_webhook_url', request.form['notifier_webhook_url'])
            set_config('notifier_send_solves', 'notifier_send_solves' in request.form)
            set_config('notifier_send_notifications', 'notifier_send_notifications' in request.form)
            return redirect(request.url)

        return render_template('admin_chat_notifier.html',
            supported_notifier_types=NOTIFIER_CLASSES.keys(),
            notifier_type=get_config('notifier_type'),
            notifier_webhook_url=get_config('notifier_webhook_url'),
            notifier_send_solves=get_config('notifier_send_solves'),
            notifier_send_notifications=get_config('notifier_send_notifications'),
            nonce=session['nonce'])

    app.register_blueprint(admin_chat_notifier)

    def chal_solve_decorator(chal_solve_func):
        @wraps(chal_solve_func)
        def wrapper(*args, **kwargs):
            chal_solve_func(*args, **kwargs)

            notifier = get_configured_notifier()
            if notifier and bool(get_config('notifier_send_solves')):
                if get_mode_as_word() == TEAMS_MODE:
                    solver = kwargs['team']
                    solver_url = url_for("teams.public", team_id=solver.account_id, _external=True)
                else:
                    solver = kwargs['user']
                    solver_url = url_for("users.public", user_id=solver.account_id, _external=True)
                challenge = kwargs['challenge']
                challenge_url = challenge_url='{url_for_listing}#{challenge.name}-{challenge.id}'.format(url_for_listing=url_for('challenges.listing', _external=True), challenge=challenge)

                notifier.notify_solve(solver.name, solver_url, challenge.name, challenge_url)
        return wrapper
    BaseChallenge.solve = chal_solve_decorator(BaseChallenge.solve)

    def event_publish_decorator(event_publish_func):
        @wraps(event_publish_func)
        def wrapper(*args, **kwargs):
            event_publish_func(args, kwargs)

            if kwargs['type'] == 'notification':
                notifier = get_configured_notifier()
                if notifier and bool(get_config('notifier_send_notifications')):
                    notification = kwargs['data']
                    notifier.notify_message(notification['title'], notification['content'])
        return wrapper
    app.events_manager.publish = event_publish_decorator(app.events_manager.publish)
