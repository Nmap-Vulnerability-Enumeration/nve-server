import device
import json
import pprint


with open("device_decoder_tester.json", "r") as f:
    reference_objects = json.load(f, cls = device.DeviceDecoder)

class DeviceTester:
    @staticmethod
    def all():
        try:
            print("Testing Device Class...")
            DeviceTester.test_encoder()
            DeviceTester.test_decoder()
            print("All test's passed!")
            return 0
        except:
            return -1

    @staticmethod
    def test_encoder():
        pass

    @staticmethod
    def test_decoder():
        pass

if __name__ == "__main__":
    DeviceTester.all()