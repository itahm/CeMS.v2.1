package com.itahm.nms.command;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import com.itahm.http.Response;
import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;
import com.itahm.nms.Commander;

public class Remove implements Executor {
	private final Map<String, Executor> map = new HashMap<>();
	
	public Remove(Commander agent) {
		map.put("BRANCH", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws JSONException, SQLException {
				agent.removeBranch(request.getLong("id"));
			}
			
		});
		
		map.put("FACILITY", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws JSONException, SQLException {
				agent.removeFacility(request.getLong("id"));
			}
			
		});
		
		map.put("GROUP", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws JSONException, SQLException {
				agent.removeGroup(request.getLong("id"));
			}
			
		});
		
		map.put("ICON", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection) {
				if (!agent.removeIcon(request.getString("type"))) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				}
			}
			
		});
		
		map.put("LINK", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection) {
				if (!agent.removeLink(request.getLong("id"))) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				};
			}
			
		});
		
		map.put("LOCATION", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection) {
				if (!agent.removeLocation(request.getLong("node"))) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				};
			}
			
		});
		
		map.put("NODE", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection) {
				if (!agent.removeNode(request.getLong("id"))) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				}
			}
			
		});
		
		map.put("PATH", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection) {
				if (!agent.removePath(request.getLong("id"))) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				}
			}
			
		});
		
		map.put("PROFILE", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection) {
				if (!agent.removeProfile(request.getString("name"))) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				}
			}
			
		});
		
		map.put("RACK", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection) {
				if (!agent.removeRack(request.getInt("id"))) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				}
			}
			
		});
		
		map.put("USER", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				String id = request.getString("id");
				
				if (id.equals(session.getString("id"))) {
					response.setStatus(HttpServletResponse.SC_FORBIDDEN);
				} else {
					agent.removeUser(request.getString("id"));
				}
			}
			
		});
		
		map.put("VIEW", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				agent.removeView(request.getString("user"), request.getLong("branch"));
			}
			
		});
	}
	
	@Override
	public void execute(Response response, JSONObject request, JSONObject session, Connection connection) throws SQLException {
		String target = request.getString("target");
		Executor executor = this.map.get(target.toUpperCase());
		
		if (executor == null) {
			throw new JSONException("Target is not found.");
		} else if (session.getInt("level") > 0) {
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		} else {
			executor.execute(response, request, session, connection);
			
			try (PreparedStatement pstmt = connection.prepareStatement("INSERT INTO"+
				" t_audit values (?, 'remove', ?, ?);")) {
				pstmt.setString(1, session.getString("id"));
				pstmt.setString(2, target);
				pstmt.setLong(3, System.currentTimeMillis());
				
				pstmt.executeUpdate();
			}
		}
	}
}
