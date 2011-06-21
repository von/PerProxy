"""Perspectives Excptions"""

class PerspectivesException(Exception):
    pass

class FingerprintException(PerspectivesException):
    """Exception related to a server fingerprint"""
    pass

class NotaryException(PerspectivesException):
    """Exception related to a Notary"""
    pass

class NotaryResponseException(NotaryException):
    """Exception related to NotaryResponse"""
    pass

class NotaryUnknownServiceException(NotaryResponseException):
    """Notary knows nothing about service"""
    pass

class NotaryResponseBadSignature(NotaryResponseException):
    """Verification of notary signature failed"""
    pass
