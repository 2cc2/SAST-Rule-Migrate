
from flask import Flask, request, make_response
# Initialize the Flask application
app = Flask(__name__)

@app.route('/')
def index():
    return "Test endpoints: /1 (set_cookie), /2 (set_cookie_header)"

@app.route("/1")
def set_cookie():
    # request.args["name"]  # 用户输入是一个 source
    # BAD: User input is used to set the cookie's name and value
    resp = make_response("Cookie set via set_cookie")
    if "name" in request.args:
        # resp.set_cookie(name, value)  # 未验证的用户输入到达 sink
        resp.set_cookie(request.args["name"],
                        value=request.args["name"])
    return resp

@app.route("/2")
def set_cookie_header():
    # BAD: User input is used to set the raw cookie header. Highly vulnerable to Header Injection.
    resp = make_response("Cookie set via raw header")
    if "name" in request.args:
        resp.headers['Set-Cookie'] = f"{request.args['name']}={request.args['name']};"
    return resp

if __name__ == "__main__":
    # Not runnable here, but included for complete Flask app structure
    pass
