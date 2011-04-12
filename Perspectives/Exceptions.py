"""Perspectives Excptions"""

class PerspectivesException(Exception):
    pass

class NotaryException(PerspectivesException):
    """Exception related to a Notary"""
    pass

class NotaryResponseException(PerspectivesException):
    """Exception related to NotaryResponse"""
    pass

class NotaryUnknownServiceException(NotaryResponseException):
    """Notary knows nothing about service"""
    pass

class NotaryResponseBadSignature(NotaryResponseException):
    """Verification of notary signature failed"""
    pass
