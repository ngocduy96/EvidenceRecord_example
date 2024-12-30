package vn.mobileid.pkix.ers;

public class ExpUtil
{
    static IllegalStateException createIllegalState(String message, Throwable cause)
    {
        return new IllegalStateException(message, cause);
    }
}
