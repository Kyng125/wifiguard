def test_device_list_summary_and_derived_fields(seeded):
    r = seeded.get("/api/devices?pageSize=100").get_json()
    assert r["summary"]["total"] == 42 and len(r["items"]) == 42
    by_mac = {d["macAddress"]: d for d in r["items"]}
    registry = by_mac["A4:83:E7:2D:90:16"]
    assert (registry["ownerLabel"], registry["ip"], registry["vendor"], registry["status"]) == (
        "Registry-Laptop", "192.168.1.15", "Apple", "authorised")
    assert registry["accessPoint"] == "Admin Block"
    random_dev = by_mac["9A:2E:77:1B:C4:05"]
    assert (random_dev["status"], random_dev["ip"], random_dev["vendor"]) == ("unrecognised", None, "Private (randomised)")
    assert by_mac["3C:52:82:1A:80:11"]["offline"] is True and by_mac["3C:52:82:1A:7B:09"]["offline"] is False


def test_device_filters(seeded):
    assert seeded.get("/api/devices?status=unrecognised").get_json()["total"] == 4
    assert seeded.get("/api/devices?status=under_review").get_json()["total"] == 2
    assert seeded.get("/api/devices?status=offline").get_json()["total"] == 4
    assert seeded.get("/api/devices?q=printer").get_json()["total"] == 1      # case-insensitive label match
    assert seeded.get("/api/devices?q=192.168.1.15").get_json()["total"] == 1
    assert seeded.get("/api/devices?q=zzz").get_json()["total"] == 0


def test_authorise_then_remove_a_device(seeded):
    mac = "9A:2E:77:1B:C4:05"
    r = seeded.patch(f"/api/devices/{mac.lower()}", {"status": "authorised"})
    assert r.status_code == 200 and r.get_json()["status"] == "authorised"
    assert seeded.get("/api/overview").get_json()["devices"]["authorised"] == 37
    assert seeded.delete(f"/api/devices/authorised/{mac}").status_code == 200
    assert seeded.get(f"/api/devices/{mac}").get_json()["status"] == "unrecognised"
    assert seeded.delete(f"/api/devices/authorised/{mac}").status_code == 404


def test_under_review_only_for_unauthorised(seeded):
    assert seeded.patch("/api/devices/3C:52:82:1A:7B:09", {"status": "under_review"}).status_code == 409
    r = seeded.patch("/api/devices/9A:2E:77:1B:C4:06", {"status": "under_review"})
    assert r.get_json()["status"] == "under_review"


def test_add_authorised_device_validation(seeded):
    ok = seeded.post("/api/devices/authorised", {"macAddress": "aa-bb-cc-dd-ee-02", "ownerLabel": "Test", "deviceType": "laptop"})
    assert ok.status_code == 201 and ok.get_json()["macAddress"] == "AA:BB:CC:DD:EE:02"
    dup = seeded.post("/api/devices/authorised", {"macAddress": "AA:BB:CC:DD:EE:02"})
    assert dup.status_code == 409 and dup.get_json()["error"]["code"] == "already_authorised"
    for bad in ("nonsense", "AA:BB:CC:DD:EE", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01"):
        assert seeded.post("/api/devices/authorised", {"macAddress": bad}).status_code == 422, bad
    assert seeded.post("/api/devices/authorised", {"macAddress": "AA:BB:CC:DD:EE:03", "deviceType": "toaster"}).status_code == 422


def test_device_detail_notes_and_events(seeded):
    mac = "9A:2E:77:1B:C4:05"
    seeded.post(f"/api/devices/{mac}/notes", {"text": "Seen near lab door"})
    d = seeded.get(f"/api/devices/{mac}").get_json()
    assert d["notes"][0]["text"] == "Seen near lab door"
    assert [e["id"] for e in d["events"]] == ["EV-1052"]
    assert seeded.get("/api/devices/AA:BB:CC:00:00:99").status_code == 404


def test_authorise_all_devices(seeded):
    assert seeded.post("/api/devices/authorise-all").get_json() == {"authorised": 6}
    s = seeded.get("/api/overview").get_json()["devices"]
    assert (s["authorised"], s["unrecognised"], s["underReview"]) == (42, 0, 0)


def test_access_point_statuses_and_reason(seeded):
    r = seeded.get("/api/access-points").get_json()
    assert r["summary"] == {"total": 8, "authorised": 6, "suspectedRogue": 1, "neighbouring": 1, "offline": 1}
    by = {a["bssid"]: a for a in r["items"]}
    rogue = by["7C:10:C9:5E:3A:92"]
    assert rogue["status"] == "suspected_rogue"
    assert rogue["reason"] == "Known SSID from an unknown BSSID; security differs from the authorised WPA3"
    assert by["9A:4B:21:C7:0D:36"]["status"] == "neighbouring"
    assert by["28:6C:07:4A:12:44"]["status"] == "offline"
    assert r["items"][0]["bssid"] == "7C:10:C9:5E:3A:92"      # rogue first


def test_access_point_actions(seeded):
    bssid = "7C:10:C9:5E:3A:92"
    assert seeded.patch(f"/api/access-points/{bssid}", {"status": "neighbouring"}).get_json()["status"] == "neighbouring"
    assert seeded.get("/api/overview").get_json()["accessPoints"]["suspectedRogue"] == 0
    assert seeded.patch(f"/api/access-points/{bssid}", {"status": "authorised"}).get_json()["authorised"] is True
    assert seeded.patch(f"/api/access-points/{bssid}", {"status": "neighbouring"}).status_code == 409
    assert seeded.delete(f"/api/access-points/authorised/{bssid}").status_code == 200
    assert seeded.get(f"/api/access-points/{bssid}").get_json()["status"] == "suspected_rogue"


def test_access_point_detail_and_add(seeded):
    d = seeded.get("/api/access-points/28:6C:07:4A:12:08").get_json()
    assert d["location"] == "Lab 1" and d["devices"] and "28:6C:07:4A:12:08" == d["bssid"]
    assert [e["id"] for e in seeded.get("/api/access-points/7C:10:C9:5E:3A:92").get_json()["events"]] == ["EV-1053"]
    created = seeded.post("/api/access-points/authorised", {"ssid": "Annex", "bssid": "28:6C:07:4A:99:01",
                                                            "channel": 6, "securityMode": "WPA3", "location": "Annex"})
    assert created.status_code == 201 and created.get_json()["status"] == "offline"   # never heard yet
    assert seeded.post("/api/access-points/authorised", {"ssid": "Annex", "bssid": "28:6C:07:4A:99:01"}).status_code == 409
    assert seeded.post("/api/access-points/authorised", {"ssid": "A" * 33, "bssid": "28:6C:07:4A:99:02"}).status_code == 422
    assert seeded.post("/api/access-points/authorised", {"ssid": "X", "bssid": "28:6C:07:4A:99:03", "channel": 999}).status_code == 422


def test_authorise_all_access_points_skips_rogue(seeded):
    # Authorised access points already exist, so the suspected rogue is skipped and the neighbour is left alone.
    assert seeded.post("/api/access-points/authorise-all").get_json() == {"authorised": 0, "skipped": 1}
    assert seeded.get("/api/overview").get_json()["accessPoints"]["suspectedRogue"] == 1


def test_topology(seeded):
    t = seeded.get("/api/topology").get_json()
    assert len(t["accessPoints"]) == 8 and len(t["devices"]) == 42
