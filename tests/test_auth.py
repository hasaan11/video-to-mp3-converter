import pytest
from auth.auth import JWTDecodeError, JWTTokenExpiredError, create_jwt_token, decode_jwt_token, token_has_expired
@pytest.fixture(autouse=True)
def setup_test_env():
    import os
    os.environ['JWT_TOKEN_KEY'] = 'test_secret'
    os.environ['JWT_EXPIRATION_TIME'] = '100'

class TestJwtFunctions:
    """
    Test suite for JWT authentication functions.
    
    This class contains tests for token creation, decoding,
    expiration handling, and tampering detection to ensure
    the robustness and security of the JWT implementation.
    """

    @pytest.fixture
    def valid_user_data(self):
        return {'username': 'test_user', 'email':'test_user@example.com'}
    
    def test_create_jwt_token(self, valid_user_data):

        jwt_token = create_jwt_token(valid_user_data)

        assert len(jwt_token.split('.')) == 3
        
        decoded_user_data = decode_jwt_token(jwt_token)

        assert 'username' in decoded_user_data
        assert 'email' in decoded_user_data
        assert 'exp' in decoded_user_data

        assert decoded_user_data['username'] == valid_user_data['username']
        assert decoded_user_data['email'] == valid_user_data['email']



    @pytest.mark.parametrize("invalid_token", ['invalid_token', 'random gibberish', '12389uoadnjkasndnasn83onadjnjkdnas'])
    def test_decode_jwt_token_invalid(self, invalid_token):
        with pytest.raises(JWTDecodeError):
            decode_jwt_token(invalid_token)

    
    def test_token_expiration(self, valid_user_data):
        import os
        import time

        os.environ['JWT_EXPIRATION_TIME'] = '10'

        token = create_jwt_token(valid_user_data)
        time.sleep(12)

        with pytest.raises(JWTTokenExpiredError):
            decode_jwt_token(token)

        os.environ['JWT_EXPIRATION_TIME'] = '1000'
        token = create_jwt_token(valid_user_data)
        user_data = decode_jwt_token(token)
        assert not token_has_expired(user_data['exp'])



    def test_token_tampering(self, valid_user_data):
        import os
        import random

        os.environ['JWT_EXPIRATION_TIME'] = '100'
        token = create_jwt_token(valid_user_data)

        token_list = list(token)

        random_index = random.randrange(len(token))

        original_char = token_list[random_index]
        new_char = chr((ord(original_char) + 1) % 128) 
        token_list[random_index] = new_char

        modified_token = ''.join(token_list)

        with pytest.raises(JWTDecodeError):
            decode_jwt_token(modified_token)

