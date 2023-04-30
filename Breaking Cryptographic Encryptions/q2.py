from q2_atm import ATM, ServerResponse


def extract_PIN(encrypted_PIN) -> int:
    """Extracts the original PIN string from an encrypted PIN."""
    x = ATM()
    for j in range(10000):
        j = int(str(j).zfill(4))
        if x.encrypt_PIN(j) == encrypted_PIN:
            return j
    return -1  # not supposed to happen


def extract_credit_card(encrypted_credit_card) -> int:
    """Extracts a credit card number string from its ciphertext."""
    x = ATM()
    e = x.rsa_card.e #3 in the given ATM !
    return round(pow(encrypted_credit_card, 1/e)) #m = (c)^1/e

def forge_signature():
    """Forge a server response that passes verification."""
    # Return a ServerResponse instance.
    res = ServerResponse(ATM.CODE_APPROVAL, ATM.CODE_APPROVAL) #todo change 5
    return res
    


