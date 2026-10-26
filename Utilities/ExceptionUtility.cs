namespace SekiroArchiveInspector.Utilities;

public static class ExceptionUtility
{
    public static void PrintExceptionDetails(
        Exception ex,
        int depth = 0)
    {
        string indent = new(' ', depth * 2);

        Console.Error.WriteLine(
            $"{indent}{ex.GetType().FullName}: {ex.Message}");

        if (!string.IsNullOrWhiteSpace(ex.StackTrace))
        {
            Console.Error.WriteLine($"{indent}Stack trace:");
            Console.Error.WriteLine(ex.StackTrace);
        }

        if (ex is AggregateException aggregate)
        {
            foreach (Exception inner in aggregate.InnerExceptions)
            {
                Console.Error.WriteLine(
                    $"{indent}Inner exception:");

                PrintExceptionDetails(inner, depth + 1);
            }
        }
        else if (ex.InnerException != null)
        {
            Console.Error.WriteLine(
                $"{indent}Inner exception:");

            PrintExceptionDetails(
                ex.InnerException,
                depth + 1);
        }
    }
}
