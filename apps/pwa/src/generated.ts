// Generated from crates/blackspace-protocol. Do not edit by hand.
export interface paths {
    "/v1/deposit/envelopes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_deposit_envelope"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/deposit/key-packages/claim": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_claim_key_package"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/enroll/parcels": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_park_enrollment_parcel"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/enroll/parcels/claim": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_claim_enrollment_parcel"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/enroll/parcels/{parcel_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put: operations["api_finalize_enrollment_parcel"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/info": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["api_server_info"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailbox/ack": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_acknowledge_envelopes"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailbox/deposit-capabilities": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_create_deposit_capability"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailbox/deposit-capabilities/{capability_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        delete: operations["api_revoke_deposit_capability"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailbox/devices": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["api_list_devices"];
        put?: never;
        post: operations["api_register_device"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailbox/devices/secure-reset": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_secure_device_reset"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailbox/key-packages": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_publish_key_packages"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailbox/mls-state": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["api_get_mls_state"];
        put: operations["api_put_mls_state"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailbox/pull": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_pull_envelopes"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailbox/read-capability/rotate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_rotate_read_capability"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailbox/recover": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_recover_mailbox"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/mailboxes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["api_provision_mailbox"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        AckRequestV1: {
            acknowledgement_tokens: string[];
        };
        AckResponseV1: {
            /** Format: int64 */
            acknowledged: number;
        };
        ClaimEnrollmentParcelResponseV1: {
            ciphertext?: string | null;
            eph_pub: string;
            nonce?: string | null;
            size_class?: number | null;
            status: components["schemas"]["EnrollmentParcelStatusV1"];
        };
        ClaimKeyPackageResponseV1: {
            key_package: components["schemas"]["KeyPackageV1"];
        };
        CreateDepositCapabilityRequestV1: {
            /** Format: int64 */
            expires_at?: number | null;
            verifier: string;
        };
        CreateDepositCapabilityResponseV1: {
            /** Format: uuid */
            capability_id: string;
        };
        DepositAcceptedV1: {
            accepted: boolean;
        };
        DepositTargetV1: {
            deposit_capability: string;
            https_url?: string | null;
            onion_url: string;
        };
        DeviceV1: {
            /** Format: int64 */
            enrolled_at: number;
            /** Format: uuid */
            id: string;
            label: string;
            revoked: boolean;
        };
        /** @enum {string} */
        EnrollmentParcelStatusV1: "pending_confirmation" | "ready";
        EnvelopeV1: {
            ciphertext: string;
            /** Format: uuid */
            envelope_id: string;
            /** Format: int64 */
            expires_at: number;
            size_class: number;
            /** Format: int32 */
            version: number;
        };
        FeatureFlagsV1: {
            companion_linking: boolean;
            key_packages: boolean;
            mls: boolean;
            /**
             * @description Floating-primary multi-device: shared MLS-state CAS blob + one-scan enrollment.
             *     Defaulted so a client can still parse an older server's /v1/info without it.
             */
            multi_device?: boolean;
            opaque_transport: boolean;
            recovery_takeover: boolean;
            registration_invites: boolean;
        };
        /**
         * @description Stage two of enrollment, uploaded only after the trusted device confirms the
         *     SAS. The payload is encrypted to the new device's ephemeral public key.
         */
        FinalizeEnrollmentParcelRequestV1: {
            ciphertext: string;
            nonce: string;
            size_class: number;
        };
        /**
         * @description An opaque, client-signed MLS key package. The mailbox validates bounds and
         *     expiry; the claiming client authenticates it against `identity_public_key`.
         */
        KeyPackageV1: {
            ciphersuite: string;
            /** Format: int64 */
            expires_at: number;
            identity_public_key: string;
            key_package: string;
            /** Format: uuid */
            package_id: string;
            /** Format: int32 */
            protocol_version: number;
        };
        ListDevicesResponseV1: {
            devices: components["schemas"]["DeviceV1"][];
        };
        MailboxProvisionRequestV1: {
            admin_capability_verifier: string;
            identity_public_key: string;
            initial_deposit_capability_verifier: string;
            /** Format: int64 */
            initial_deposit_expires_at?: number | null;
            key_packages: components["schemas"]["KeyPackageV1"][];
            read_capability_verifier: string;
        };
        MailboxProvisionResponseV1: {
            /** Format: uuid */
            initial_deposit_capability_id: string;
            /** Format: uuid */
            mailbox_id: string;
        };
        /**
         * @description The shared, client-encrypted MLS client state. `version` is a monotonically
         *     increasing compare-and-swap counter: only the latest is stored (older ratchet
         *     states are overwritten, limiting the forward-secrecy exposure of at-rest state).
         */
        MlsStateResponseV1: {
            ciphertext: string;
            size_class: number;
            /** Format: int64 */
            version: number;
        };
        /**
         * @description Stage one of enrollment. Only the trusted device's ephemeral public key is
         *     parked here. No reusable account secret is uploaded until both screens have
         *     displayed the same short-authentication string and the trusted user approves.
         */
        ParkEnrollmentParcelRequestV1: {
            eph_pub: string;
            /** Format: int64 */
            expires_at: number;
            parcel_verifier: string;
        };
        ParkEnrollmentParcelResponseV1: {
            /** Format: uuid */
            parcel_id: string;
        };
        ProblemV1: {
            code: string;
            message: string;
        };
        PublishKeyPackagesRequestV1: {
            key_packages: components["schemas"]["KeyPackageV1"][];
        };
        PublishKeyPackagesResponseV1: {
            /** Format: int32 */
            accepted: number;
            /** Format: int32 */
            available: number;
        };
        PullRequestV1: {
            /** Format: int32 */
            limit?: number | null;
        };
        PullResponseV1: {
            envelopes: components["schemas"]["PulledEnvelopeV1"][];
        };
        PulledEnvelopeV1: {
            acknowledgement_token: string;
            ciphertext: string;
            /** Format: uuid */
            deposit_capability_id: string;
            /** Format: uuid */
            envelope_id: string;
            /** Format: int64 */
            expires_at: number;
            size_class: number;
            /** Format: int32 */
            version: number;
        };
        /**
         * @description Compare-and-swap write of the shared MLS state. The write succeeds only when
         *     `expected_version` equals the currently stored version (0 for the first write);
         *     otherwise the server returns 409 and the client re-reads before retrying. This
         *     is what makes a ratchet fork impossible across concurrent devices.
         */
        PutMlsStateRequestV1: {
            ciphertext: string;
            /** Format: int64 */
            expected_version: number;
            size_class: number;
        };
        PutMlsStateResponseV1: {
            /** Format: int64 */
            version: number;
        };
        RecoverMailboxRequestV1: {
            admin_capability_verifier: string;
            deposit_capabilities: components["schemas"]["CreateDepositCapabilityRequestV1"][];
            identity_public_key: string;
            key_packages: components["schemas"]["KeyPackageV1"][];
            read_capability_verifier: string;
        };
        RecoverMailboxResponseV1: {
            deposit_capability_ids: string[];
            /** Format: uuid */
            mailbox_id: string;
            /** Format: int64 */
            purged_envelopes: number;
        };
        RegisterDeviceRequestV1: {
            /** Format: uuid */
            device_id: string;
            label: string;
        };
        /**
         * @description Rotate only the mailbox read capability. Used to cut a linked companion's
         *     read access on unlink without the destructive full recovery/takeover flow.
         */
        RotateReadCapabilityRequestV1: {
            read_capability_verifier: string;
        };
        RotateReadCapabilityResponseV1: {
            ok: boolean;
        };
        /**
         * @description Atomically replaces the shared mailbox credentials and re-encrypts the shared
         *     MLS state under a new account root. Because v1 devices share mailbox-wide
         *     credentials, every device except the caller is revoked and must be re-enrolled.
         */
        SecureDeviceResetRequestV1: {
            admin_capability_verifier: string;
            /** Format: uuid */
            current_device_id: string;
            /** Format: int64 */
            expected_mls_state_version: number;
            mls_state_ciphertext: string;
            mls_state_size_class: number;
            read_capability_verifier: string;
            revoke_deposit_capability_ids?: string[];
        };
        SecureDeviceResetResponseV1: {
            /** Format: int64 */
            revoked_devices: number;
            /** Format: int64 */
            version: number;
        };
        ServerInfoV1: {
            /** Format: int64 */
            default_retention_seconds: number;
            envelope_size_classes: number[];
            features: components["schemas"]["FeatureFlagsV1"];
            https_origin?: string | null;
            instance_name: string;
            maximum_envelope_bytes: number;
            /** Format: int32 */
            maximum_pull_batch: number;
            /** Format: int64 */
            maximum_queued_envelopes: number;
            /** Format: int64 */
            maximum_retention_seconds: number;
            onion_origin?: string | null;
            protocol_versions: number[];
        };
        /** @enum {string} */
        TransportMode: "tor-native" | "tor-web" | "https-web" | "compatibility-web-dev";
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    api_deposit_envelope: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/blackspace-envelope+json": components["schemas"]["EnvelopeV1"];
            };
        };
        responses: {
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DepositAcceptedV1"];
                };
            };
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_claim_key_package: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClaimKeyPackageResponseV1"];
                };
            };
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_park_enrollment_parcel: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ParkEnrollmentParcelRequestV1"];
            };
        };
        responses: {
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ParkEnrollmentParcelResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_claim_enrollment_parcel: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClaimEnrollmentParcelResponseV1"];
                };
            };
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_finalize_enrollment_parcel: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                parcel_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["FinalizeEnrollmentParcelRequestV1"];
            };
        };
        responses: {
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_server_info: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ServerInfoV1"];
                };
            };
        };
    };
    api_acknowledge_envelopes: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AckRequestV1"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AckResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_create_deposit_capability: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreateDepositCapabilityRequestV1"];
            };
        };
        responses: {
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CreateDepositCapabilityResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_revoke_deposit_capability: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                capability_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_list_devices: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListDevicesResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_register_device: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RegisterDeviceRequestV1"];
            };
        };
        responses: {
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_secure_device_reset: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SecureDeviceResetRequestV1"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SecureDeviceResetResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_publish_key_packages: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PublishKeyPackagesRequestV1"];
            };
        };
        responses: {
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PublishKeyPackagesResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_get_mls_state: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MlsStateResponseV1"];
                };
            };
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_put_mls_state: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PutMlsStateRequestV1"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PutMlsStateResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_pull_envelopes: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PullRequestV1"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PullResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_rotate_read_capability: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RotateReadCapabilityRequestV1"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RotateReadCapabilityResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_recover_mailbox: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RecoverMailboxRequestV1"];
            };
        };
        responses: {
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoverMailboxResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
    api_provision_mailbox: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["MailboxProvisionRequestV1"];
            };
        };
        responses: {
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MailboxProvisionResponseV1"];
                };
            };
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProblemV1"];
                };
            };
        };
    };
}
