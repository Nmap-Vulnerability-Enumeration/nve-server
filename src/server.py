import src.device as device
import flask
import src.vulnerability as vulnerability

from flask import request, jsonify, make_response
from src.nmap_scanner import NmapScanner

# Create some test data for our catalog in the form of a list of dictionaries.
books = [
    {'id': 0,
    'title': 'A Fire Upon the Deep',
    'author': 'Vernor Vinge',
    'first_sentence': 'The coldsleep itself was dreamless.',
    'year_published': '1992'},
    {'id': 1,
    'title': 'The Ones Who Walk Away From Omelas',
    'author': 'Ursula K. Le Guin',
    'first_sentence': 'With a clamor of bells that set the swallows soaring, the Festival of Summer came to the city Omelas, bright-towered by the sea.',
    'published': '1973'},
    {'id': 2,
    'title': 'Dhalgren',
    'author': 'Samuel R. Delany',
    'first_sentence': 'to wound the autumnal city.',
    'published': '1975'}
]

class NVEServer:
    def __init__(self, nmap_scanner: NmapScanner = None):
        self._scanner = nmap_scanner
        self._num_requests = 0

    def increment_req(self):
        self._num_requests += 1
    
    def start(self):
        app = flask.Flask(__name__)
        app.config["DEBUG"] = True

        @app.route('/', methods=['GET'])
        def home():
            return "<h1>Distant Reading Archive</h1><p>This site is a prototype API for distant reading of science fiction novels.</p>"

        @app.route("/api/v1/setup", methods=["POST"])
        def setup_scanner():
            print(request.form)
            if "deviceIP" not in request.form or "subnet" not in request.form:
                data = {'message': "Error: please provide deviceIP and subnet"}
                return make_response(jsonify(data), 400)
            
            if self._scanner == None:
                self._scanner = NmapScanner(default_ip=request.form["deviceIP"],
                                            default_snet_mask=request.form["subnet"])
            else:
                data = {'message': "Error: scanner already set up"}
                return make_response(jsonify(data), 500)


            data = {'message': 'Created', 'code': 'SUCCESS'}
            return make_response(jsonify(data), 201)

        # A route to return all of the available entries in our catalog.
        @app.route('/api/v1/devices/all', methods=['GET'])
        def api_device_all():
            try:
                devices = self._scanner.get_all_devices()
                return jsonify(books, cls = device.DeviceEncoder)
            except:
                data = {'message': "Error"}
                return make_response(jsonify(data), 500)

        @app.route('/api/v1/device', methods=['GET'])
        def api_device_discovery_ip():
            # Check if an ID was provided as part of the URL.
            # If ID is provided, assign it to a variable.
            # If no ID is provided, display an error in the browser.
            if 'discovery_ip' in request.args:
                ips = request.args['discovery_ip']

                response = dict()
                for ip in ips:
                    try:
                        val = self._scanner.get_device()
                    except:
                        pass
            else:
                data = {'message': "Error: No discovery_id field provided. Please specify an discovery_id."}
                return make_response(jsonify(data), 401)

            # Create an empty list for our results
            results = []

            # Loop through the data and match results that fit the requested ID.
            # IDs are unique, but other fields might return many results
            for book in books:
                if book['id'] == id:
                    results.append(book)

            # Use the jsonify function from Flask to convert our list of
            # Python dictionaries to the JSON format.
            return jsonify(results)
        
        @app.route('/shutdown', methods=['GET'])
        def shutdown():
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()
            return 'Server shutting down...'

        app.run()