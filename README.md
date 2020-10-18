# CTFd Chat Notifier

A small CTFd plugin to send notifications to Slack or Discord about solves and admin announcements. Can be easily extended to support other platforms.

## Installation

Clone this repo to `CTFd/plugins/CTFd_chat_notifier` in your CTFd installation directory and restart it. You should see the notifier settings in the admin panel.

Tested with CTFd 3.1.1.

## Extending

In your plugin, create a class that extends from `BaseNotifier` and implement the `notify_solve` and `notify_message` methods. Add an instance of this class to the `NOTIFIER_CLASSES` dictionary.

## TODO
(contributions welcome!)

* Telegram support
* Support per-chat-service configuration
* Add a threshold above which solve notifications will stop being sent (otherwise it may get quite irritating with 'sanity check' type challenges)
* Add "this is the Nth solve" option
