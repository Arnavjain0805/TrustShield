import cv2
import os
import time
import urllib.request

VIDEO_DIR = "data/videos"
os.makedirs(VIDEO_DIR, exist_ok=True)

CASCADE_FILE = "haarcascade_frontalface_default.xml"
CASCADE_PATH = os.path.join("data", CASCADE_FILE)

if not os.path.exists(CASCADE_PATH):
    print(f"Downloading {CASCADE_FILE}...")
    url = f"https://raw.githubusercontent.com/opencv/opencv/master/data/haarcascades/{CASCADE_FILE}"
    try:
        urllib.request.urlretrieve(url, CASCADE_PATH)
    except Exception as e:
        # Fallback to cv2 data if download fails
        CASCADE_PATH = cv2.data.haarcascades + CASCADE_FILE


def capture_video(username, duration=5):
    """
    Capture a short video of the user for face registration.
    Returns path to the saved video or None if failed.
    """
    file_path = os.path.join(VIDEO_DIR, f"user_{username}.avi")

    # Delete previous file if exists
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except PermissionError:
            print(f"Cannot delete {file_path}, file in use")
            return None

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Cannot access webcam")
        return None

    # Video writer
    fourcc = cv2.VideoWriter_fourcc(*"XVID")
    fps = 20.0
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    out = cv2.VideoWriter(file_path, fourcc, fps, (width, height))

    start_time = time.time()
    face_detected = False
    face_cascade = cv2.CascadeClassifier(CASCADE_PATH)

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, 1.3, 5)
        if len(faces) > 0:
            face_detected = True

        out.write(frame)

        # Stop after duration seconds
        if time.time() - start_time > duration:
            break

    # Release resources properly
    cap.release()
    out.release()
    # cv2.destroyAllWindows()

    if face_detected:
        return file_path
    else:
        # If no face detected, remove the video safely
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except PermissionError:
                print(f"Cannot delete {file_path}, file in use")
        return None

def verify_video(user_id):
    """Check if registered video exists (to be extended with recognition)."""
    file_path = os.path.join(VIDEO_DIR, f"user_{user_id}.avi")
    return os.path.exists(file_path)
