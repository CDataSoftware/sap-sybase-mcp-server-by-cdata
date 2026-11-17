package com.cdata.mcp;

import java.util.regex.Pattern;

/**
 * Validates SQL queries to ensure only read-only SELECT statements are executed.
 * Used by RunQueryTool to enforce security constraints.
 */
public class SqlValidator {

  // Pattern to detect dangerous SQL statements (case-insensitive)
  // Blocks: INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, TRUNCATE, EXEC, EXECUTE, GRANT, REVOKE, MERGE, CALL
  private static final Pattern DANGEROUS_SQL_PATTERN = Pattern.compile(
      "^\\s*(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE|GRANT|REVOKE|MERGE|CALL)\\b",
      Pattern.CASE_INSENSITIVE
  );

  // Pattern to validate SELECT statement (must start with SELECT or WITH for CTEs)
  private static final Pattern SELECT_PATTERN = Pattern.compile(
      "^\\s*(SELECT|WITH)\\b",
      Pattern.CASE_INSENSITIVE
  );

  /**
   * Validates that the SQL is a read-only SELECT statement.
   * @param sql The SQL to validate
   * @throws SecurityException if the SQL is not a valid SELECT statement
   */
  public static void validateSelectOnly(String sql) {
    if (sql == null || sql.trim().isEmpty()) {
      throw new SecurityException("SQL query cannot be empty");
    }

    String trimmed = sql.trim();

    // Check for dangerous statements
    if (DANGEROUS_SQL_PATTERN.matcher(trimmed).find()) {
      throw new SecurityException("Only SELECT queries are allowed. DML and DDL statements are blocked.");
    }

    // Verify it starts with SELECT or WITH (for CTEs)
    if (!SELECT_PATTERN.matcher(trimmed).find()) {
      throw new SecurityException("Query must be a SELECT statement");
    }

    // Block semicolons to prevent statement chaining
    if (trimmed.contains(";")) {
      // Allow semicolon only at the very end
      String withoutTrailingSemicolon = trimmed.replaceAll(";\\s*$", "");
      if (withoutTrailingSemicolon.contains(";")) {
        throw new SecurityException("Multiple statements are not allowed");
      }
    }
  }

  /**
   * Checks if the SQL would pass validation without throwing.
   * @param sql The SQL to check
   * @return true if the SQL is valid, false otherwise
   */
  public static boolean isValidSelectQuery(String sql) {
    try {
      validateSelectOnly(sql);
      return true;
    } catch (SecurityException e) {
      return false;
    }
  }
}
