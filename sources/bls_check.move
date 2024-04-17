module storage_bls::bls_check {

    use std::option;
    use aptos_std::bls12381;

    /// Signature verification failed
    const EINVALID_SIGNATURE: u64 = 11;

    public entry fun verify_bls_signature(signature: vector<u8>, public_key: vector<u8>, msg: vector<u8>) {
        let result = bls12381::verify_normal_signature(
            &bls12381::signature_from_bytes(signature),
            &option::extract(&mut bls12381::public_key_from_bytes(public_key)),
            msg
        );
        assert!(result, EINVALID_SIGNATURE);
    }

    public entry fun check_bls_signature() {
        let signature = vector[173, 191, 193, 130, 222, 147, 13, 247, 36, 205, 115, 218, 163, 157, 178, 205, 9, 86, 150, 51, 151, 74, 213, 237, 45, 106, 78, 173,
            229, 229, 117, 211, 210, 107, 65, 78, 73, 39, 254, 175, 142, 85, 169, 171, 100, 164, 72, 28, 16, 151, 74, 125, 152, 133, 239, 222, 254, 210, 67, 243, 69,
            93, 51, 179, 45, 99, 192, 32, 19, 221, 17, 189, 129, 182, 128, 116, 195, 57, 195, 203, 3, 126, 161, 47, 107, 137, 231, 92, 224, 118, 248, 107, 103, 29,
            119, 122];
        let public_key = vector[163, 44, 81, 2, 99, 5, 114, 138, 174, 20, 255, 112, 148, 180, 60, 255, 240, 95, 253, 197, 127, 95, 221, 235, 68, 240,
            157, 18, 140, 132, 10, 209, 114, 136, 136, 214, 174, 160, 31, 237, 194, 102, 99, 80, 151, 72, 64, 10];
        let msg = vector[202, 235, 137, 156, 136, 77, 198, 81, 97, 245, 30, 150, 58, 242, 111, 208, 139, 125, 75, 148, 214, 107, 112, 245, 116, 49, 51, 165, 62, 147, 77, 179];
        let result = bls12381::verify_normal_signature(
            &bls12381::signature_from_bytes(signature),
            &option::extract(&mut bls12381::public_key_from_bytes(public_key)),
            msg
        );
        assert!(result, EINVALID_SIGNATURE);
    }
}
