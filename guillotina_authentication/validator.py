import jwt
from guillotina.auth import find_user


class JWTKeyCloakValidator:
    for_validators = ("bearer")

    async def validate(self, token):
        if token.get("type") not in ("bearer"):
            return

        if "." not in token.get("token", ""):
            # quick way to check if actually might be jwt
            return

        try:
            validated_jwt = jwt.decode(token["token"], verify=False)
            token["id"] = validated_jwt.get("id", validated_jwt.get("sub"))
            token["decoded"] = validated_jwt
            user = await find_user(token)
            if user is not None and user.id == token["id"]:
                return user
        except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError, KeyError):
            pass

        return

