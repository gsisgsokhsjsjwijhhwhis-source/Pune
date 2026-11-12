"""Regression tests for authentication and device-registry security."""
import os
import re
import tempfile
import unittest

_TEST_DB = tempfile.NamedTemporaryFile(prefix="pune-registry-test-", suffix=".db", delete=False)
_TEST_DB.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _TEST_DB.name
os.environ["SECRET_KEY"] = "test-only-secret-key"
os.environ.pop("RENDER", None)

from device_registry.app import (  # noqa: E402
    app,
    db,
    User,
    Device,
    is_valid_imei,
    safe_return_url,
)

app.config.update(TESTING=True)


class DeviceRegistryTests(unittest.TestCase):
    def setUp(self):
        with app.app_context():
            db.drop_all()
            db.create_all()
            first = User(
                full_name="Registry Owner",
                email="owner@example.test",
                phone="+911234567890",
                is_profile_completed=True,
            )
            second = User(
                full_name="Other User",
                email="other@example.test",
                phone="+919876543210",
                is_profile_completed=True,
            )
            db.session.add_all([first, second])
            db.session.commit()
            self.owner_id = first.id
            self.other_id = second.id
            device = Device(
                imei="490154203237518",
                brand="Test",
                model="Phone",
                status="NOT_FOR_SALE",
                user_id=first.id,
            )
            db.session.add(device)
            db.session.commit()
            self.device_id = device.id
        self.client = app.test_client()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def token(self, response):
        match = re.search(
            rb'name="_csrf_token" value="([^"]+)"',
            response.data,
        )
        self.assertIsNotNone(match, "Rendered form must include a CSRF token")
        return match.group(1).decode("ascii")

    def sign_in_as(self, user_id):
        with self.client.session_transaction() as session:
            session["user_id"] = user_id

    def test_imei_luhn_validation(self):
        self.assertTrue(is_valid_imei("490154203237518"))
        self.assertFalse(is_valid_imei("490154203237519"))
        self.assertFalse(is_valid_imei("49015420323751"))
        self.assertFalse(is_valid_imei("49015420323751x"))

    def test_health_endpoint_checks_database(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"status": "ok"})

    def test_state_changing_request_requires_csrf(self):
        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 400)

        page = self.client.get("/admin/login")
        token = self.token(page)
        response = self.client.post("/logout", data={"_csrf_token": token})
        self.assertEqual(response.status_code, 302)

    def test_logout_is_not_available_as_get(self):
        response = self.client.get("/logout")
        self.assertEqual(response.status_code, 405)

    def test_device_registration_validates_imei(self):
        self.sign_in_as(self.owner_id)
        page = self.client.get("/")
        token = self.token(page)

        invalid = self.client.post(
            "/register-device",
            data={
                "_csrf_token": token,
                "brand": "Example",
                "model": "Invalid IMEI",
                "imei": "123456789012345",
                "status": "NOT_FOR_SALE",
            },
        )
        self.assertEqual(invalid.status_code, 302)

        valid = self.client.post(
            "/register-device",
            data={
                "_csrf_token": token,
                "brand": "Example",
                "model": "Valid IMEI",
                "imei": "356938035643809",
                "status": "NOT_FOR_SALE",
            },
        )
        self.assertEqual(valid.status_code, 302)
        with app.app_context():
            self.assertIsNotNone(Device.query.filter_by(imei="356938035643809").first())

    def test_user_cannot_change_another_users_device(self):
        self.sign_in_as(self.other_id)
        page = self.client.get("/")
        token = self.token(page)
        response = self.client.post(
            f"/update-status/{self.device_id}",
            data={"_csrf_token": token, "status": "FOR_SALE"},
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            device = db.session.get(Device, self.device_id)
            self.assertEqual(device.status, "NOT_FOR_SALE")

    def test_safe_return_url_rejects_external_referrer(self):
        with app.test_request_context(
            "/",
            headers={"Referer": "https://attacker.example/steal-session"},
        ):
            self.assertEqual(safe_return_url(), "/")

    def test_owner_can_delete_only_own_device(self):
        self.sign_in_as(self.owner_id)
        page = self.client.get("/")
        token = self.token(page)
        response = self.client.post(
            f"/delete-device/{self.device_id}",
            data={"_csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            self.assertIsNone(db.session.get(Device, self.device_id))

    def test_user_cannot_delete_another_users_device(self):
        self.sign_in_as(self.other_id)
        page = self.client.get("/")
        token = self.token(page)
        response = self.client.post(
            f"/delete-device/{self.device_id}",
            data={"_csrf_token": token},
        )
        self.assertEqual(response.status_code, 403)
        with app.app_context():
            self.assertIsNotNone(db.session.get(Device, self.device_id))

    def test_admin_can_delete_any_device(self):
        from device_registry.app import AdminSetting
        with app.app_context():
            db.session.add(AdminSetting(username="root", password_hash="not-used"))
            db.session.commit()
        with self.client.session_transaction() as session:
            session["admin_authenticated"] = True
        page = self.client.get("/")
        token = self.token(page)
        response = self.client.post(
            f"/delete-device/{self.device_id}",
            data={"_csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            self.assertIsNone(db.session.get(Device, self.device_id))

    def test_delete_requires_csrf(self):
        self.sign_in_as(self.owner_id)
        response = self.client.post(f"/delete-device/{self.device_id}")
        self.assertEqual(response.status_code, 400)
        with app.app_context():
            self.assertIsNotNone(db.session.get(Device, self.device_id))


if __name__ == "__main__":
    unittest.main()
