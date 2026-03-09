# About Application Services login

Encrypted Application Services/Bridges currently leverage the `m.login.application_service` login type to create devices for users.
This API is *not* available in the Palpo Authentication Service.

We're working on a solution to support this use case, but in the meantime, this means **encrypted bridges will not work with the Palpo Authentication Service.**
A workaround is to disable E2EE support in your bridge setup.
