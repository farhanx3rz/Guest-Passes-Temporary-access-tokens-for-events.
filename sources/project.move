module MyModule::GuestPass {
    use aptos_framework::signer;
    use aptos_framework::timestamp;
    use aptos_std::table;
    use aptos_framework::event;

    /// Error codes (simple u64s for assert!)
    const E_PASS_EXPIRED: u64 = 1;
    const E_PASS_NOT_FOUND: u64 = 2;
    const E_UNAUTHORIZED: u64 = 3;
    const E_ALREADY_ISSUED: u64 = 4;
    const E_INVALID_DURATION: u64 = 5;

    /// A single-use guest pass resource stored under the RECIPIENT
    struct GuestPass has key, store {
        event_id: u64,       // Unique identifier for the event
        expiry_time: u64,    // Epoch seconds when the pass expires
        issuer: address,     // Issuer (organizer) address
        is_active: bool,     // Single-use flag
    }

    /// Issuer-owned staging: recipient address -> staged GuestPass
    struct Pending has key {
        by_recipient: table::Table<address, GuestPass>,
    }

    /// Event emitted when validating a guest pass
    #[event]
    struct ValidationEvent has copy, drop, store {
        user: address,
        event_id: u64,
        is_valid: bool,
    }

    /// Call once per issuer to publish their staging table
    public entry fun init(issuer: &signer) {
        let issuer_addr = signer::address_of(issuer);
        assert!(!exists<Pending>(issuer_addr), E_UNAUTHORIZED);
        move_to(issuer, Pending {
            by_recipient: table::new<address, GuestPass>(),
        });
    }

    /// ISSUER: stage a pass for `recipient` (recipient must later claim it)
    public entry fun issue_guest_pass(
        issuer: &signer,
        recipient: address,
        event_id: u64,
        duration_seconds: u64
    ) acquires Pending {
        assert!(duration_seconds > 0, E_INVALID_DURATION);

        let issuer_addr = signer::address_of(issuer);
        let pending = borrow_global_mut<Pending>(issuer_addr);

        let now = timestamp::now_seconds();

        if (table::contains(&pending.by_recipient, recipient)) {
            // If there’s already a staged pass, only allow if it’s inactive
            let gp_ref = table::borrow_mut(&mut pending.by_recipient, recipient);
            assert!(!gp_ref.is_active, E_ALREADY_ISSUED);

            // Re-initialize in place
            gp_ref.event_id = event_id;
            gp_ref.expiry_time = now + duration_seconds;
            gp_ref.issuer = issuer_addr;
            gp_ref.is_active = true;
            return;
        };

        let pass = GuestPass {
            event_id,
            expiry_time: now + duration_seconds,
            issuer: issuer_addr,
            is_active: true,
        };
        table::add(&mut pending.by_recipient, recipient, pass);
    }

    /// RECIPIENT: claim your staged pass from an issuer into your own account
    public entry fun claim_guest_pass(
        recipient: &signer,
        issuer_addr: address
    ) acquires Pending {
        let r = signer::address_of(recipient);
        let pending = borrow_global_mut<Pending>(issuer_addr);

        // Remove from staging (must exist), then move under recipient
        let gp = table::remove(&mut pending.by_recipient, r);
        move_to(recipient, gp);
    }

    /// Validate and consume (single-use) a guest pass stored under the caller
    public entry fun validate_guest_pass(user: &signer, event_id: u64) acquires GuestPass {
        let user_addr = signer::address_of(user);

        // Check if GuestPass exists
        if (!exists<GuestPass>(user_addr)) {
            event::emit(ValidationEvent { user: user_addr, event_id, is_valid: false });
            return
        };

        let gp = borrow_global_mut<GuestPass>(user_addr);

        // Must match event and be active
        if (gp.event_id != event_id || !gp.is_active) {
            event::emit(ValidationEvent { user: user_addr, event_id, is_valid: false });
            return
        };

        // Expired?
        let now = timestamp::now_seconds();
        if (now >= gp.expiry_time) {
            gp.is_active = false;  // Mark expired
            event::emit(ValidationEvent { user: user_addr, event_id, is_valid: false });
            return
        };

        // Success → consume single use
        gp.is_active = false;
        event::emit(ValidationEvent { user: user_addr, event_id, is_valid: true });
    }
}