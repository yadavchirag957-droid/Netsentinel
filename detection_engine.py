class DetectionEngine:

    def __init__(self, detectors):
        self.detectors = detectors

    def detect(self, event, features=None):

        detections = []

        for detector in self.detectors:

            try:
                result = detector.detect(
                    event,
                    features
                )

            except Exception as error:
                print(
                    f"[!] Detector error in "
                    f"{detector.__class__.__name__}: {error}"
                )
                continue

            if result:
                detections.append(result)

        return detections
