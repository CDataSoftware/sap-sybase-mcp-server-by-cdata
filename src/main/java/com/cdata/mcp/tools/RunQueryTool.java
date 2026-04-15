package com.cdata.mcp.tools;

import com.cdata.mcp.*;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class RunQueryTool implements ITool {
  private Config config;
  private Logger logger = LoggerFactory.getLogger(RunQueryTool.class);

  // Pattern to detect dangerous SQL statements (case-insensitive)
  // Blocks: INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, TRUNCATE, EXEC, EXECUTE, GRANT, REVOKE
  private static final Pattern DANGEROUS_SQL_PATTERN = Pattern.compile(
      "^\\s*(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE|GRANT|REVOKE|MERGE|CALL)\\b",
      Pattern.CASE_INSENSITIVE
  );

  // Pattern to validate SELECT statement (must start with SELECT or WITH for CTEs)
  private static final Pattern SELECT_PATTERN = Pattern.compile(
      "^\\s*(SELECT|WITH)\\b",
      Pattern.CASE_INSENSITIVE
  );

  public RunQueryTool(Config config) {
    this.config = config;
  }

  /**
   * Validates that the SQL is a read-only SELECT statement.
   * @param sql The SQL to validate
   * @throws SecurityException if the SQL is not a valid SELECT statement
   */
  private void validateSelectOnly(String sql) {
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

  @Override
  public void register(McpServer.SyncSpec mcp) throws Exception {
    String quotes = this.config.getIdentifierQuotes();
    String prefix = this.config.getPrefix();
    String description = "The SELECT statement to execute. "
        + "Use the `" + prefix + "_get_tables` tool to get a list of available tables, "
        + "and the `" + prefix + "_get_columns` tool to list table columns. "
        + "The SQL dialect is mostly based around SQL-92. "
        + "Identifiers should be quoted using `" + quotes + "` characters. "
        + "Valid clauses: FROM, INNER JOIN, LEFT JOIN, GROUP BY, ORDER BY, LIMIT/OFFSET. "
        + Constants.FORMAT_DESC;

    String schema = new JsonSchemaBuilder()
        .addString("sql", description)
        .build();
    mcp.tool(
        new Tool(
            prefix + "_run_query",
            "Execute a SQL SELECT statement.",
            schema
        ),
        this::run
    );
  }

  @Override
  public McpSchema.CallToolResult run(Map<String, Object> args) {
    String sql = (String)args.get("sql");
    // Log only that a query was executed, not the full query content (may contain PII)
    this.logger.info("RunQueryTool executing query");
    this.logger.debug("RunQueryTool query: {}", sql);

    try {
      // Validate that this is a SELECT-only query
      validateSelectOnly(sql);

      try (Connection cn = config.newConnection()) {
        // Set connection to read-only mode for defense in depth
        cn.setReadOnly(true);

        List<McpSchema.Content> content = new ArrayList<>();
        String csv = queryToCsv(cn, sql);

        List<McpSchema.Role> roles = new ArrayList<>();
        roles.add(McpSchema.Role.USER);
        content.add(
            new McpSchema.TextContent(roles, 1.0, csv)
        );
        return new McpSchema.CallToolResult(content, false);
      }
    } catch (SecurityException ex) {
      // Security violations get specific error messages
      this.logger.warn("Query blocked by security validation: {}", ex.getMessage());
      throw new RuntimeException("Security error: " + ex.getMessage());
    } catch (Exception ex) {
      // Generic error for other exceptions to avoid leaking schema info
      this.logger.error("Query execution failed", ex);
      throw new RuntimeException("Query execution failed. Check server logs for details.");
    }
  }

  private String queryToCsv(Connection cn, String sql) throws SQLException {
    try (Statement st = cn.createStatement()) {
      return CsvUtils.resultSetToCsv(st.executeQuery(sql));
    }
  }

}
