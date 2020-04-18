#!/usr/bin/python3
import requests
from flask import Flask
from flask import jsonify, request
from attackerkb_api import AttackerKB
from secrets import SLACK_TOKENS, ATTACKERKB_API, PRIVATE


application = Flask(__name__)

api = AttackerKB(ATTACKERKB_API)


@application.route("/")
def home():
    return "This is a slack APP Your in the wrong place"

@application.route("/assessment", methods=["POST"])
def assesment_cve():
    request_token = request.form.get('token')

    print(request_token)

    if PRIVATE:
        if request_token not in SLACK_TOKENS:
            return "Not a valid Token"

    cve_id = request.form.get("text")
    topic_details = api.get_topics(name=cve_id)

    # Check for a valid CVE
    valid = False
    if cve_id.lower().startswith("cve"):
        valid = True

    if valid and len(topic_details) >= 1:
        topic_details = topic_details[0]

    # Put a better regex in here. 
    if not valid:
        return jsonify(
            {
                "response_type": "in_channel",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Sorry!* _{0}_ is not a valid CVE ID".format(cve_id)
                        }
                    }
                ]
            }
        )

    topic_id = topic_details['id']

    top_assessment = api.get_assessments(size=1, order="score:desc", topicId=topic_id)[0]

    json_response = {
        "response_type": "in_channel",
        "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*{0}*\n{1}".format(topic_details['name'], topic_details['document'])
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Attacker Value:*\n{0}".format(topic_details['score']['attackerValue'])
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*Exploitability:*\n{0}".format(topic_details['score']['exploitability'])
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*Report Link*\nhttps://attackerkb.com/topics/{0}".format(topic_details["id"])
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Top Voted Assesment*\n{0}".format(top_assessment["document"])
                    }
                },
            ]
        }

    
    return jsonify(json_response)



@application.route("/top10", methods=["POST"])
def top_ten():
    request_token = request.form.get('token')
    if PRIVATE:
        if request_token not in SLACK_TOKENS:
            return "Not a valid Token"

@application.route("/cve", methods=["POST"])
def get_cve():
    request_token = request.form.get('token')
    if PRIVATE:
        if request_token not in SLACK_TOKENS:
            return "Not a valid Token"

    cve_id = request.form.get("text")
    topic_details = api.get_topics(name=cve_id)

    # Check for a valid CVE
    valid = False
    if cve_id.lower().startswith("cve"):
        valid = True

    if valid and len(topic_details) >= 1:
        topic_details = topic_details[0]

    # Put a better regex in here. 
    if not valid:
        return jsonify(
            {
                "response_type": "in_channel",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Sorry!* _{0}_ is not a valid CVE ID".format(cve_id)
                        }
                    }
                ]
            }
        )

    print(topic_details)

    json_response = {
        "response_type": "in_channel",
        "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*{0}*\n{1}".format(topic_details['name'], topic_details['document'])
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Attacker Value:*\n{0}".format(topic_details['score']['attackerValue'])
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*Exploitability:*\n{0}".format(topic_details['score']['exploitability'])
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*Report Link*\nhttps://attackerkb.com/topics/{0}".format(topic_details["id"])
                        }
                    ]
                }
            ]
        }

    
    return jsonify(json_response)






@application.route("/contributor", methods=["POST"])
def get_contributor():
    request_token = request.form.get('token')
    if PRIVATE:
        if request_token not in SLACK_TOKENS:
            return "Not a valid Token"
    
    user_id = request.form.get('text')
    user_details = api.get_single_contributor(user_id)

    response_json = {
        "response_type": "in_channel",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Contributor details for *{0}*".format(user_id)
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Username: {0}\nScore: {1}".format(user_details['username'], user_details['score'])
                },
                "accessory": {
                    "type": "image",
                    "image_url": user_details["avatar"],
                    "alt_text": "User Avatar"
                }
            }
        ]
        }


    return jsonify(response_json)


if __name__ == "__main__":
    application.run(host='0.0.0.0', debug=True)
