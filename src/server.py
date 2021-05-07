import src.device as device
import flask
import src.vulnerability as vulnerability

from flask import request, jsonify, make_response
from src.nmap_scanner import NmapScanner

class NVEServer:
    def __init__(self, nmap_scanner: NmapScanner = None):
        self._scanner = nmap_scanner
        self._num_requests = 0

    def increment_req(self):
        self._num_requests += 1
    
    def start(self):
        app = flask.Flask(__name__)
        app.config["DEBUG"] = True

        # @app.route('/', methods=['GET'])
        # def home():
        #     return "<h1>Distant Reading Archive</h1><p>This site is a prototype API for distant reading of science fiction novels.</p>"

        @app.route("/api/v1/setup", methods=["POST"])
        def setup_scanner():
            print(request.form)
            if "deviceIP" not in request.form or "subnet" not in request.form:
                data = {'message': "Error: please provide deviceIP and subnet"}
                return make_response(jsonify(data), 400)
            
            if self._scanner == None:
                self._scanner = NmapScanner(default_ip=request.form["deviceIP"],
                                            default_snet_mask=request.form["subnet"])
                return "OK", 200
            else:
                data = {'message': "scanner already set up"}
                return make_response(jsonify(data), 200)


            data = {'message': 'Created', 'code': 'SUCCESS'}
            return make_response(jsonify(data), 201)

        # A route to return all of the available entries in our catalog.
        @app.route('/api/v1/devices/all', methods=['GET'])
        def api_device_all():
            try:
                devices = self._scanner.get_all_devices()
                return device.DeviceEncoder().encode(devices)
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

                if not isinstance(ips, list):
                    return device.DeviceEncoder().encode([self._scanner.get_device(ips)]), 200

                response = []
                for ip in ips:
                    response.append(self._scanner.get_device(ip))
                return device.DeviceEncoder().encode(response), 200
            else:
                data = {'message': "Error: No discovery_id field provided. Please specify an discovery_id."}
                return make_response(jsonify(data), 401)
        
        @app.route('/api/v1/device/vuln', methods=['GET'])
        def api_device_vuln_discovery_ip():
            # Check if an ID was provided as part of the URL.
            # If ID is provided, assign it to a variable.
            # If no ID is provided, display an error in the browser.
            if 'discovery_ip' in request.args:
                ips = request.args['discovery_ip']

                if not isinstance(ips, list):
                    return vulnerability.VulnerabilityEncoder().encode([self._scanner.get_device_vuln(ips)]), 200
                
                response = dict()
                for ip in ips:
                    response[ip] = self._scanner.get_device_vuln(ip)
                return vulnerability.VulnerabilityEncoder().encode(response), 200

            else:
                data = {'message': "Error: No discovery_id field provided. Please specify an discovery_id."}
                return make_response(jsonify(data), 401)

        @app.route('/shutdown', methods=['GET'])
        def shutdown():
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()
            return 'Server shutting down...'

        print("Starting...")
        app.run()