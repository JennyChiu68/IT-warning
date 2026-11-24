"""Draw the small PNG pictograms used in both alert lists."""

from pathlib import Path

from PIL import Image, ImageDraw


SIZE = 24
SCALE = 12
ASSETS = Path(__file__).resolve().parents[1] / "miniprogram" / "assets"


class Icon:
    def __init__(self, color):
        self.image = Image.new("RGBA", (SIZE * SCALE, SIZE * SCALE))
        self.draw = ImageDraw.Draw(self.image)
        self.color = color

    @staticmethod
    def pixels(values):
        return tuple(round(value * SCALE) for value in values)

    def dot(self, x, y, radius=0.85):
        self.draw.ellipse(self.pixels((x - radius, y - radius, x + radius, y + radius)), fill=self.color)

    def line(self, *points, width=1.65, closed=False):
        path = [self.pixels(point) for point in points]
        if closed:
            path.append(path[0])
        self.draw.line(path, fill=self.color, width=round(width * SCALE), joint="curve")
        for point in (points[:1] + points[-1:]) if not closed else points:
            self.dot(*point, radius=width / 2)

    def box(self, left, top, right, bottom, radius=1.7, fill=False):
        self.draw.rounded_rectangle(
            self.pixels((left, top, right, bottom)),
            radius=round(radius * SCALE),
            fill=self.color if fill else None,
            outline=None if fill else self.color,
            width=round(1.65 * SCALE),
        )

    def arc(self, bounds, start, end, width=1.65):
        self.draw.arc(self.pixels(bounds), start, end, fill=self.color, width=round(width * SCALE))

    def solid(self, *points):
        self.draw.polygon([self.pixels(point) for point in points], fill=self.color)

    def save(self, name):
        self.image.resize((72, 72), Image.Resampling.LANCZOS).save(ASSETS / f"product-{name}.png", optimize=True)


def monai(icon):
    icon.line((4.5, 8), (4.5, 4.5), (8, 4.5))
    icon.line((16, 4.5), (19.5, 4.5), (19.5, 8))
    icon.line((4.5, 16), (4.5, 19.5), (8, 19.5))
    icon.line((16, 19.5), (19.5, 19.5), (19.5, 16))
    icon.line((9, 12), (15, 12), width=2.2)
    icon.line((12, 9), (12, 15), width=2.2)


def mail(icon):
    icon.box(3.5, 5.5, 20.5, 17.5)
    icon.line((4.8, 7.2), (12, 12.8), (19.2, 7.2))
    icon.line((13.8, 17.5), (16.4, 20), (21, 15.2), width=2)


def vmware(icon):
    icon.line((11, 7.5), (11, 4.5), (20, 4.5), (20, 13.5), (16.5, 13.5))
    icon.box(4, 10.5, 13, 19.5, radius=1.2)
    icon.line((7.5, 13.5), (10, 13.5), (10, 16.2), width=1.25)


def experiment(icon):
    icon.box(4, 4.5, 20, 19.5)
    icon.line((12, 5.2), (12, 18.8))
    icon.line((6.8, 15), (9.2, 15), width=1.75)
    icon.line((14.8, 12), (17.2, 12), width=1.75)
    icon.dot(8, 10, 1.15)
    icon.dot(16, 8.5, 1.15)


def elephant(icon):
    icon.line((4, 16.5), (4, 10), (6.5, 7), (10, 6), (14.5, 6), (17.5, 8.2),
              (18.5, 11), (18.5, 16.5), (20.2, 17.5), (21, 15.8))
    icon.line((4, 16.5), (7, 18.4), (11.5, 18.4), (11.5, 15.8))
    icon.arc((8, 8.8, 14.5, 16.2), 70, 253)
    icon.dot(16.1, 10.6, 0.8)


def proxy(icon):
    icon.line((12, 3.6), (20, 8.1), (20, 15.9), (12, 20.4), (4, 15.9), (4, 8.1), closed=True)
    icon.line((7.5, 10), (15.5, 10), (13.6, 8.1), width=1.5)
    icon.line((16.5, 14), (8.5, 14), (10.4, 15.9), width=1.5)


def node(icon):
    icon.line((12, 3.7), (19.5, 8), (19.5, 16), (12, 20.3), (4.5, 16), (4.5, 8), closed=True)
    icon.line((8.2, 13.5), (12, 9.6), (15.8, 13.5), width=1.35)
    for x, y in [(8.2, 13.5), (12, 9.6), (15.8, 13.5)]:
        icon.dot(x, y, 1.3)


def coffee(icon):
    icon.line((5.2, 11), (15.4, 11), (15.4, 15.3), (13, 17.6), (7.6, 17.6), (5.2, 15.3), (5.2, 11))
    icon.arc((13.4, 11, 20.2, 16.5), 270, 90)
    icon.line((4.4, 20), (19, 20))
    icon.line((10.5, 8.2), (10.2, 6.9), (11.8, 5.7), (11.5, 4.2), width=1.4)


def windows(icon):
    for left in [4, 12.9]:
        for top in [4, 12.9]:
            icon.box(left, top, left + 7, top + 7, radius=0.7, fill=True)


def monitor(icon):
    icon.box(3.6, 5.3, 20.4, 16)
    icon.line((12, 16), (12, 19.1))
    icon.line((8.5, 19.1), (15.5, 19.1))


def phone(icon):
    icon.box(7.1, 3.5, 16.9, 20.5)
    icon.line((10.5, 5.7), (13.5, 5.7), width=1.4)
    icon.dot(12, 17.9, 0.8)


def apple_devices(icon):
    icon.line((10.5, 15.8), (3.8, 15.8), (3.8, 5.5), (17.5, 5.5), (17.5, 8))
    icon.line((2.6, 18.2), (10.3, 18.2))
    icon.box(13.1, 10, 20.8, 20.3, radius=1.3)
    icon.dot(16.95, 18.3, 0.7)


def android(icon):
    icon.solid((4, 13.5), (20, 13.5), (20, 18), (4, 18))
    icon.draw.pieslice(icon.pixels((4, 6, 20, 22)), 180, 360, fill=icon.color)
    icon.line((7.9, 8.4), (6.3, 5.9), width=1.4)
    icon.line((16.1, 8.4), (17.7, 5.9), width=1.4)
    for x in [8.5, 15.5]:
        icon.draw.ellipse(icon.pixels((x - 0.9, 12.1, x + 0.9, 13.9)), fill=(0, 0, 0, 0))


def server(icon):
    icon.box(4, 5, 20, 11, radius=1.3)
    icon.box(4, 13, 20, 19, radius=1.3)
    icon.dot(7.4, 8, 0.85)
    icon.dot(7.4, 16, 0.85)
    icon.line((12.5, 8), (17, 8), width=1.35)
    icon.line((12.5, 16), (17, 16), width=1.35)


def terminal(icon):
    icon.box(3.8, 5.2, 20.2, 18.8)
    icon.line((7.3, 9), (10.4, 12), (7.3, 15))
    icon.line((13, 15), (16.7, 15))


def shield(icon):
    icon.line((12, 3.5), (19, 6.5), (19, 12.5), (16.7, 17.6), (12, 20.4), (7.3, 17.6), (5, 12.5), (5, 6.5), closed=True)
    icon.line((9, 12.2), (11.1, 14.3), (15.1, 10.3))


def incident(icon):
    icon.line((12, 4), (20.7, 19), (3.3, 19), closed=True)
    icon.line((12, 9.2), (12, 13.1), width=1.8)
    icon.dot(12, 16, 0.85)


PICTOGRAMS = {
    "monai": ("#6947ba", monai),
    "mailassure": ("#28739d", mail),
    "vmware": ("#0e7a66", vmware),
    "optimizely": ("#365bc0", experiment),
    "php": ("#5d4bb6", elephant),
    "nginx": ("#16805d", proxy),
    "node": ("#4e741f", node),
    "java": ("#ae5b29", coffee),
    "windows": ("#2970bb", windows),
    "macos": ("#425572", monitor),
    "ios": ("#425572", phone),
    "apple": ("#425572", apple_devices),
    "android": ("#4e741f", android),
    "server": ("#0e7a66", server),
    "runtime": ("#5d4bb6", terminal),
    "system": ("#2970bb", monitor),
    "mobile": ("#28739d", phone),
    "incident": ("#ac4439", incident),
    "security": ("#365bc0", shield),
}


if __name__ == "__main__":
    for name, (color, draw) in PICTOGRAMS.items():
        icon = Icon(color)
        draw(icon)
        icon.save(name)
