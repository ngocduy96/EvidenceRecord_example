package vn.mobile.id.ers;

public class ExpUtil
{
    static IllegalStateException createIllegalState(String message, Throwable cause)
    {
        return new IllegalStateException(message, cause);
    }
}
