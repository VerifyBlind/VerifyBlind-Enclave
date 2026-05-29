using VerifyBlind.Core.Models;
using System.Text.Json;
using Xunit;

namespace VerifyBlind.Core.Tests;

/// <summary>
/// Contract tests for the shared models. These types are the serialization boundary
/// between the mobile apps, the Relay API and the Enclave — a silently renamed JSON
/// property here breaks interop without any compiler error, so the wire-level
/// [JsonPropertyName] mappings are asserted explicitly.
/// </summary>
public class SharedModelsTests
{
    // ── PartnerRequest ────────────────────────────────────────────────────────

    [Fact]
    public void PartnerRequest_SetProperties_RoundTrips()
    {
        var pr = new PartnerRequest
        {
            Request = JsonSerializer.Deserialize<JsonElement>("{\"k\":1}"),
            Sign = "my-signature"
        };
        Assert.Equal("my-signature", pr.Sign);
        Assert.Equal(JsonValueKind.Object, pr.Request.ValueKind);
    }

    [Fact]
    public void PartnerRequest_JsonRoundTrip_Succeeds()
    {
        var pr = new PartnerRequest
        {
            Request = JsonSerializer.Deserialize<JsonElement>("{\"k\":1}"),
            Sign = "sig123"
        };
        var json = JsonSerializer.Serialize(pr);
        var deserialized = JsonSerializer.Deserialize<PartnerRequest>(json);
        Assert.Equal("sig123", deserialized!.Sign);
    }

    [Fact]
    public void PartnerRequest_UsesSnakeCaseWireNames()
    {
        var json = JsonSerializer.Serialize(new PartnerRequest
        {
            Request = JsonSerializer.Deserialize<JsonElement>("{}"),
            Sign = "s"
        });
        Assert.Contains("\"request\"", json);
        Assert.Contains("\"sign\"", json);
    }

    // ── LoginResponse ─────────────────────────────────────────────────────────

    [Fact]
    public void LoginResponse_SetProperties_Accessible()
    {
        var lr = new LoginResponse
        {
            Nonce = "nonce-xyz",
            SpecialData = new { foo = 1 },
            Validations = new Dictionary<string, object> { ["age"] = "18+", ["user_id"] = "user-abc" }
        };

        Assert.Equal("nonce-xyz", lr.Nonce);
        Assert.NotNull(lr.SpecialData);
        Assert.Equal(2, lr.Validations!.Count);
        Assert.Equal("user-abc", lr.Validations["user_id"]);
    }

    [Fact]
    public void LoginResponse_NullableFields_DefaultNull()
    {
        var lr = new LoginResponse { Nonce = "n" };
        Assert.Null(lr.SpecialData);
        Assert.Null(lr.Validations);
    }

    [Fact]
    public void LoginResponse_JsonRoundTrip_Succeeds()
    {
        var lr = new LoginResponse
        {
            Nonce = "n1",
            Validations = new Dictionary<string, object> { ["user_id"] = "u1" }
        };
        var json = JsonSerializer.Serialize(lr);
        var des = JsonSerializer.Deserialize<LoginResponse>(json);
        Assert.Equal("n1", des!.Nonce);
        Assert.Equal("u1", des.Validations!["user_id"].ToString());
    }

    [Fact]
    public void LoginResponse_NullOptionalFields_OmittedFromJson()
    {
        // [JsonIgnore(WhenWritingNull)] — a null validations/additional_data block must not
        // appear on the wire, otherwise partners receive misleading empty keys.
        var json = JsonSerializer.Serialize(new LoginResponse { Nonce = "n" });
        Assert.DoesNotContain("validations", json);
        Assert.DoesNotContain("additional_data", json);
    }

    [Fact]
    public void LoginResponse_PopulatedOptionalFields_PresentInJson()
    {
        var json = JsonSerializer.Serialize(new LoginResponse
        {
            Nonce = "n",
            Validations = new Dictionary<string, object> { ["age"] = true },
            SpecialData = new { x = 1 }
        });
        Assert.Contains("\"nonce\"", json);
        Assert.Contains("\"validations\"", json);
        Assert.Contains("\"additional_data\"", json);
    }

    // ── SignedLoginResponse ───────────────────────────────────────────────────

    [Fact]
    public void SignedLoginResponse_SetProperties_Accessible()
    {
        var slr = new SignedLoginResponse
        {
            Payload = "{\"nonce\":\"abc\"}",
            Signature = "base64-sig"
        };

        Assert.Equal("{\"nonce\":\"abc\"}", slr.Payload);
        Assert.Equal("base64-sig", slr.Signature);
    }

    [Fact]
    public void SignedLoginResponse_JsonRoundTrip_Succeeds()
    {
        var slr = new SignedLoginResponse { Payload = "p", Signature = "s" };
        var json = JsonSerializer.Serialize(slr);
        var des = JsonSerializer.Deserialize<SignedLoginResponse>(json);
        Assert.Equal("p", des!.Payload);
        Assert.Equal("s", des.Signature);
        Assert.Contains("\"payload\"", json);
        Assert.Contains("\"signature\"", json);
    }

    // ── PartnerRequestData ────────────────────────────────────────────────────

    [Fact]
    public void PartnerRequestData_OptionalProperties_Accessible()
    {
        var prd = new PartnerRequestData
        {
            PartnerId = "pid",
            Nonce = "nonce",
            PublicKey = "pubkey",
            CallbackUrl = "https://example.com/cb",
            SpecialData = new { x = 1 },
            Validations = new Dictionary<string, object> { ["age"] = "18+" }
        };

        Assert.Equal("https://example.com/cb", prd.CallbackUrl);
        Assert.NotNull(prd.SpecialData);
        Assert.Single(prd.Validations!);
    }

    [Fact]
    public void PartnerRequestData_UsesSnakeCaseWireNames()
    {
        var json = JsonSerializer.Serialize(new PartnerRequestData
        {
            PartnerId = "pid",
            Nonce = "n",
            PublicKey = "pk",
            CallbackUrl = "https://cb.test",
            SpecialData = new { x = 1 },
            Validations = new Dictionary<string, object> { ["age"] = "18+" }
        });
        Assert.Contains("\"partner_id\"", json);
        Assert.Contains("\"public_key\"", json);
        Assert.Contains("\"callback_url\"", json);
        Assert.Contains("\"additional_data\"", json);
        Assert.Contains("\"validations\"", json);
    }

    [Fact]
    public void PartnerRequestData_JsonRoundTrip_PreservesIds()
    {
        var json = JsonSerializer.Serialize(new PartnerRequestData
        {
            PartnerId = "partner-7", Nonce = "abc", PublicKey = "key"
        });
        var des = JsonSerializer.Deserialize<PartnerRequestData>(json);
        Assert.Equal("partner-7", des!.PartnerId);
        Assert.Equal("abc", des.Nonce);
        Assert.Equal("key", des.PublicKey);
    }

    // ── LoginRequest ──────────────────────────────────────────────────────────

    [Fact]
    public void LoginRequest_OptionalFields_Accessible()
    {
        var lr = new LoginRequest
        {
            EncrSignedTicket = "enc",
            Nonce = "nonce",
            IntegrityToken = "it",
            PartnerPublicKey = "ppk",
            QrPayloadJson = "{\"k\":1}",
            CallbackUrl = "https://cb.test"
        };

        Assert.Equal("ppk", lr.PartnerPublicKey);
        Assert.Equal("{\"k\":1}", lr.QrPayloadJson);
        Assert.Equal("https://cb.test", lr.CallbackUrl);
    }

    [Fact]
    public void LoginRequest_UsesSnakeCaseWireNames()
    {
        var json = JsonSerializer.Serialize(new LoginRequest
        {
            EncrSignedTicket = "enc",
            Nonce = "n",
            IntegrityToken = "it",
            PartnerPublicKey = "ppk",
            QrPayloadJson = "{}",
            ClientIpV4 = "1.2.3.4",
            ClientIpV6 = "::1"
        });
        Assert.Contains("\"encr_signed_ticket\"", json);
        Assert.Contains("\"integrity_token\"", json);
        Assert.Contains("\"partner_public_key\"", json);
        Assert.Contains("\"qr_payload_json\"", json);
        Assert.Contains("\"client_ipv4\"", json);
        Assert.Contains("\"client_ipv6\"", json);
    }

    [Fact]
    public void LoginRequest_CallbackUrl_IsNeverSerialized()
    {
        // CallbackUrl is [JsonIgnore] — an internal Relay-only field. It must never reach
        // the Enclave (or any wire payload), regardless of value.
        var json = JsonSerializer.Serialize(new LoginRequest
        {
            EncrSignedTicket = "e", Nonce = "n", CallbackUrl = "https://internal-secret.test/cb"
        });
        Assert.DoesNotContain("callback", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("internal-secret", json);
    }

    [Fact]
    public void LoginRequest_JsonRoundTrip_PreservesWireFields()
    {
        var original = new LoginRequest
        {
            EncrSignedTicket = "ticket", Nonce = "guid-nonce", QrPayloadJson = "{\"a\":1}"
        };
        var des = JsonSerializer.Deserialize<LoginRequest>(JsonSerializer.Serialize(original));
        Assert.Equal("ticket", des!.EncrSignedTicket);
        Assert.Equal("guid-nonce", des.Nonce);
        Assert.Equal("{\"a\":1}", des.QrPayloadJson);
    }

    // ── HandshakeRequest / HandshakeResponse ──────────────────────────────────

    [Fact]
    public void HandshakeRequest_UsesSnakeCaseWireNames()
    {
        var json = JsonSerializer.Serialize(new HandshakeRequest
        {
            IntegrityToken = "it", FcmToken = "fcm", Platform = "android"
        });
        Assert.Contains("\"integrity_token\"", json);
        Assert.Contains("\"fcm_token\"", json);
        Assert.Contains("\"platform\"", json);
    }

    [Fact]
    public void HandshakeResponse_UsesSnakeCaseWireNames()
    {
        var json = JsonSerializer.Serialize(new HandshakeResponse
        {
            Nonce = "n",
            Timestamp = 1234567890,
            NonceSignature = "sig",
            AttestationDocument = "att",
            Challenges = { LivenessAction.Blink, LivenessAction.Smile }
        });
        Assert.Contains("\"nonce\"", json);
        Assert.Contains("\"timestamp\"", json);
        Assert.Contains("\"nonce_signature\"", json);
        Assert.Contains("\"attestation_document\"", json);
        Assert.Contains("\"challenges\"", json);
    }

    [Fact]
    public void HandshakeResponse_JsonRoundTrip_PreservesChallenges()
    {
        var original = new HandshakeResponse
        {
            Nonce = "n", Timestamp = 42, NonceSignature = "s",
            Challenges = { LivenessAction.FaceLeft, LivenessAction.FaceRight }
        };
        var des = JsonSerializer.Deserialize<HandshakeResponse>(JsonSerializer.Serialize(original));
        Assert.Equal(2, des!.Challenges.Count);
        Assert.Equal(LivenessAction.FaceLeft, des.Challenges[0]);
        Assert.Equal(LivenessAction.FaceRight, des.Challenges[1]);
    }

    [Fact]
    public void LoginHandshakeResponse_RoundTrips()
    {
        var json = JsonSerializer.Serialize(new LoginHandshakeResponse { AttestationDocument = "att-doc" });
        Assert.Contains("\"attestation_document\"", json);
        var des = JsonSerializer.Deserialize<LoginHandshakeResponse>(json);
        Assert.Equal("att-doc", des!.AttestationDocument);
    }

    // ── LivenessAction enum ───────────────────────────────────────────────────

    [Fact]
    public void LivenessAction_NumericValues_AreStable()
    {
        // The mobile clients depend on these exact ordinals — changing them silently
        // remaps challenges (e.g. a "blink" prompt would be read as "smile").
        Assert.Equal(0, (int)LivenessAction.None);
        Assert.Equal(1, (int)LivenessAction.FaceLeft);
        Assert.Equal(2, (int)LivenessAction.FaceRight);
        Assert.Equal(3, (int)LivenessAction.Blink);
        Assert.Equal(4, (int)LivenessAction.Smile);
    }

    // ── SecurePayload ─────────────────────────────────────────────────────────

    [Fact]
    public void SecurePayload_AllProperties_RoundTripThroughJson()
    {
        var original = new SecurePayload
        {
            SOD = "sod", DG1 = "dg1", DG15 = "dg15", ActiveSig = "asig", AAChallenge = "aac",
            UserPubKey = "upk", Nonce = "nonce", Timestamp = 1700000000, NonceSignature = "nsig",
            DG2_Photo = "dg2", LivenessVideo = "lv", ZoomVideo = "zv", UserSelfie = "selfie",
            IntegrityToken = "it"
        };
        var des = JsonSerializer.Deserialize<SecurePayload>(JsonSerializer.Serialize(original));
        Assert.Equal("sod", des!.SOD);
        Assert.Equal("dg15", des.DG15);
        Assert.Equal(1700000000, des.Timestamp);
        Assert.Equal("selfie", des.UserSelfie);
        Assert.Equal("it", des.IntegrityToken);
    }

    [Fact]
    public void SecurePayload_Defaults_AreEmptyNotNull()
    {
        // All string fields default to string.Empty so the Enclave never NREs on a
        // partially-populated payload.
        var p = new SecurePayload();
        Assert.Equal(string.Empty, p.SOD);
        Assert.Equal(string.Empty, p.DG1);
        Assert.Equal(string.Empty, p.ActiveSig);
        Assert.Equal(string.Empty, p.UserSelfie);
        Assert.Equal(0, p.Timestamp);
    }

    // ── RegistrationRequest ───────────────────────────────────────────────────

    [Fact]
    public void RegistrationRequest_UsesSnakeCaseWireNames()
    {
        var json = JsonSerializer.Serialize(new RegistrationRequest
        {
            EncryptedKey = "ek", AesBlob = "blob", CountryIsoCode = "TUR"
        });
        Assert.Contains("\"encrypted_key\"", json);
        Assert.Contains("\"aes_blob\"", json);
        Assert.Contains("\"country_iso_code\"", json);
    }

    [Fact]
    public void RegistrationRequest_JsonRoundTrip_Succeeds()
    {
        var des = JsonSerializer.Deserialize<RegistrationRequest>(
            JsonSerializer.Serialize(new RegistrationRequest
            {
                EncryptedKey = "ek", AesBlob = "blob", CountryIsoCode = "DEU"
            }));
        Assert.Equal("ek", des!.EncryptedKey);
        Assert.Equal("blob", des.AesBlob);
        Assert.Equal("DEU", des.CountryIsoCode);
    }

    // ── TicketPayload / SignedTicket ──────────────────────────────────────────

    [Fact]
    public void TicketPayload_AllProperties_RoundTripThroughJson()
    {
        var original = new TicketPayload
        {
            TCKN = "12345678901",
            Ad = "AHMET",
            Soyad = "YILMAZ",
            DogumTarihi = new DateTime(1990, 1, 1),
            SeriNo = "A12345678",
            GecerlilikTarihi = new DateTime(2030, 12, 31),
            Cinsiyet = "M",
            Uyruk = "TUR",
            UserPubKey = "pubkey",
            CountryIsoCode = "TUR",
            PersonId = "person-hash",
            CardId = "card-hash",
            DocumentType = "I"
        };
        var des = JsonSerializer.Deserialize<TicketPayload>(JsonSerializer.Serialize(original));
        Assert.Equal("12345678901", des!.TCKN);
        Assert.Equal(new DateTime(1990, 1, 1), des.DogumTarihi);
        Assert.Equal(new DateTime(2030, 12, 31), des.GecerlilikTarihi);
        Assert.Equal("person-hash", des.PersonId);
        Assert.Equal("card-hash", des.CardId);
        Assert.Equal("I", des.DocumentType);
    }

    [Fact]
    public void TicketPayload_NullDocumentType_OmittedFromJson()
    {
        // [JsonIgnore(WhenWritingNull)] on DocumentType.
        var json = JsonSerializer.Serialize(new TicketPayload { TCKN = "x", DocumentType = null });
        Assert.DoesNotContain("DocumentType", json);
    }

    [Fact]
    public void TicketPayload_SetDocumentType_PresentInJson()
    {
        var json = JsonSerializer.Serialize(new TicketPayload { TCKN = "x", DocumentType = "P" });
        Assert.Contains("DocumentType", json);
    }

    [Fact]
    public void SignedTicket_JsonRoundTrip_PreservesPayloadAndSignature()
    {
        var original = new SignedTicket
        {
            Payload = new TicketPayload { TCKN = "12345678901", CountryIsoCode = "TUR", Ad = "AHMET" },
            Signature = "enclave-signature"
        };
        var des = JsonSerializer.Deserialize<SignedTicket>(JsonSerializer.Serialize(original));
        Assert.Equal("12345678901", des!.Payload.TCKN);
        Assert.Equal("AHMET", des.Payload.Ad);
        Assert.Equal("enclave-signature", des.Signature);
    }

    [Fact]
    public void SignedTicket_DefaultPayload_IsNotNull()
    {
        // Payload defaults to a fresh TicketPayload — deserialising a ticket with a missing
        // payload object must not yield null and NRE downstream.
        Assert.NotNull(new SignedTicket().Payload);
    }
}
