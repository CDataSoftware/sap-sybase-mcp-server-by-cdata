package com.cdata.mcp.tests;

import org.junit.Assert;
import org.junit.Test;

import java.util.regex.Pattern;

/**
 * Tests for SQL validation logic used in RunQueryTool.
 * These tests verify the regex patterns without needing the full tool context.
 */
public class SqlValidationTests {

  // Mirror the patterns from RunQueryTool for testing
  private static final Pattern DANGEROUS_SQL_PATTERN = Pattern.compile(
      "^\\s*(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE|GRANT|REVOKE|MERGE|CALL)\\b",
      Pattern.CASE_INSENSITIVE
  );

  private static final Pattern SELECT_PATTERN = Pattern.compile(
      "^\\s*(SELECT|WITH)\\b",
      Pattern.CASE_INSENSITIVE
  );

  private void assertSqlBlocked(String sql, String description) {
    boolean hasDangerous = DANGEROUS_SQL_PATTERN.matcher(sql.trim()).find();
    boolean isSelect = SELECT_PATTERN.matcher(sql.trim()).find();

    if (hasDangerous || !isSelect) {
      // Expected - SQL should be blocked
      return;
    }
    Assert.fail("SQL should have been blocked: " + description + " - " + sql);
  }

  private void assertSqlAllowed(String sql, String description) {
    boolean hasDangerous = DANGEROUS_SQL_PATTERN.matcher(sql.trim()).find();
    boolean isSelect = SELECT_PATTERN.matcher(sql.trim()).find();

    Assert.assertFalse("SQL should not match dangerous pattern: " + description, hasDangerous);
    Assert.assertTrue("SQL should match SELECT pattern: " + description, isSelect);
  }

  // Valid SELECT queries
  @Test
  public void simpleSelectAllowed() {
    assertSqlAllowed("SELECT * FROM users", "Simple SELECT");
  }

  @Test
  public void selectWithWhereAllowed() {
    assertSqlAllowed("SELECT id, name FROM users WHERE active = 1", "SELECT with WHERE");
  }

  @Test
  public void selectWithJoinAllowed() {
    assertSqlAllowed("SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id", "SELECT with JOIN");
  }

  @Test
  public void selectWithSubqueryAllowed() {
    assertSqlAllowed("SELECT * FROM (SELECT id FROM users) AS subq", "SELECT with subquery");
  }

  @Test
  public void selectWithCTEAllowed() {
    assertSqlAllowed("WITH cte AS (SELECT id FROM users) SELECT * FROM cte", "SELECT with CTE");
  }

  @Test
  public void selectWithLeadingWhitespaceAllowed() {
    assertSqlAllowed("   SELECT * FROM users", "SELECT with leading whitespace");
  }

  @Test
  public void selectLowercaseAllowed() {
    assertSqlAllowed("select * from users", "Lowercase SELECT");
  }

  // Blocked DML statements
  @Test
  public void insertBlocked() {
    assertSqlBlocked("INSERT INTO users (name) VALUES ('test')", "INSERT statement");
  }

  @Test
  public void updateBlocked() {
    assertSqlBlocked("UPDATE users SET name = 'test'", "UPDATE statement");
  }

  @Test
  public void deleteBlocked() {
    assertSqlBlocked("DELETE FROM users WHERE id = 1", "DELETE statement");
  }

  @Test
  public void mergeBlocked() {
    assertSqlBlocked("MERGE INTO target USING source ON (1=1) WHEN MATCHED THEN UPDATE SET x=1", "MERGE statement");
  }

  // Blocked DDL statements
  @Test
  public void dropTableBlocked() {
    assertSqlBlocked("DROP TABLE users", "DROP TABLE");
  }

  @Test
  public void createTableBlocked() {
    assertSqlBlocked("CREATE TABLE evil (id INT)", "CREATE TABLE");
  }

  @Test
  public void alterTableBlocked() {
    assertSqlBlocked("ALTER TABLE users ADD COLUMN evil VARCHAR(100)", "ALTER TABLE");
  }

  @Test
  public void truncateBlocked() {
    assertSqlBlocked("TRUNCATE TABLE users", "TRUNCATE");
  }

  // Blocked procedure execution
  @Test
  public void execBlocked() {
    assertSqlBlocked("EXEC sp_executesql N'DROP TABLE users'", "EXEC");
  }

  @Test
  public void executeBlocked() {
    assertSqlBlocked("EXECUTE sp_help", "EXECUTE");
  }

  @Test
  public void callBlocked() {
    assertSqlBlocked("CALL dangerous_procedure()", "CALL");
  }

  // Blocked privilege statements
  @Test
  public void grantBlocked() {
    assertSqlBlocked("GRANT ALL ON users TO public", "GRANT");
  }

  @Test
  public void revokeBlocked() {
    assertSqlBlocked("REVOKE ALL ON users FROM public", "REVOKE");
  }

  // Case insensitivity
  @Test
  public void insertUppercaseBlocked() {
    assertSqlBlocked("INSERT INTO users VALUES (1)", "INSERT uppercase");
  }

  @Test
  public void insertLowercaseBlocked() {
    assertSqlBlocked("insert into users values (1)", "INSERT lowercase");
  }

  @Test
  public void insertMixedCaseBlocked() {
    assertSqlBlocked("InSeRt into users values (1)", "INSERT mixed case");
  }

  // Edge cases - keywords in data should not trigger false positives
  @Test
  public void selectWithInsertInStringAllowed() {
    assertSqlAllowed("SELECT * FROM users WHERE name = 'INSERT test'", "SELECT with INSERT in string literal");
  }

  @Test
  public void selectWithDeleteInColumnNameAllowed() {
    assertSqlAllowed("SELECT delete_flag FROM users", "SELECT with delete in column name");
  }

  // Non-SELECT statements should be blocked
  @Test
  public void showBlocked() {
    assertSqlBlocked("SHOW TABLES", "SHOW TABLES");
  }

  @Test
  public void describeBlocked() {
    assertSqlBlocked("DESCRIBE users", "DESCRIBE");
  }

  @Test
  public void setBlocked() {
    assertSqlBlocked("SET @var = 1", "SET statement");
  }
}
