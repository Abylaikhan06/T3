def validate_password(value: str) -> str:
    if len(value) < 8 or len(value.encode("utf-8")) > 72:
        raise ValueError("Password must be 8 to 72 bytes long")
    if not any(character.islower() for character in value):
        raise ValueError("Password must contain a lowercase letter")
    if not any(character.isupper() for character in value):
        raise ValueError("Password must contain an uppercase letter")
    if not any(character.isdigit() for character in value):
        raise ValueError("Password must contain a digit")
    if not any(not character.isalnum() for character in value):
        raise ValueError("Password must contain a special character")
    return value


def normalize_name(value: str) -> str:
    value = " ".join(value.split())
    if len(value) < 2 or len(value) > 120:
        raise ValueError("Full name must contain from 2 to 120 characters")
    if not all(character.isalpha() or character in " -'" for character in value):
        raise ValueError("Full name may contain only letters, spaces, apostrophes and hyphens")
    return value
