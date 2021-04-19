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

public class Add implements Executor{
	private final Map<String, Executor> map = new HashMap<>();
	
	public Add(Commander agent) {
		
		map.put("BRANCH", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				JSONObject branch = agent.addBranch(request.getJSONObject("branch"));
				
				response.write(branch);
			}
			
		});
		
		map.put("FACILITY", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				JSONObject facility = agent.addFacility(request.getJSONObject("facility"));
				
				response.write(facility);
			}
			
		});

		map.put("GROUP", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				JSONObject group = agent.addGroup(request.getJSONObject("group"));
				
				response.write(group);
			}
			
		});
		
		map.put("ICON", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				JSONObject icon = agent.addIcon(request.getString("type"), request.getJSONObject("icon"));
				
				if (icon == null) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				} else {
					response.write(icon);
				}
			}
			
		});
		
		map.put("LINK", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				JSONObject link = agent.addLink(request.getLong("path"));
					
				response.write(link);
			}
			
		});
		
		map.put("NODE", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				JSONObject node = agent.addNode(request.getJSONObject("node"));
				
				response.write(node);
			}
			
		});
		
		map.put("PATH", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				JSONObject path = agent.addPath(request.getJSONObject("path"));
				
				if (path == null) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				} else {
					response.write(path);
				}
			}
			
		});
		
		map.put("PROFILE", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				if (!agent.addProfile(request.getString("name"), request.getJSONObject("profile"))) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				}
			}
			
		});
		
		map.put("RACK", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				JSONObject rack = agent.addRack(request.getJSONObject("rack"));
				
				response.write(rack);
			}
			
		});
		
		map.put("USER", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				if (!agent.addUser(request.getString("id"), request.getJSONObject("user"))) {
					response.setStatus(HttpServletResponse.SC_CONFLICT);
				}
			}
			
		});
		
		map.put("VIEW", new Executor() {

			@Override
			public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
				throws SQLException {
				JSONObject view = agent.addView(request.getJSONObject("view"));
				
				response.write(view);
			}
			
		});
	}
	
	@Override
	public void execute(Response response, JSONObject request, JSONObject session, Connection connection)
		throws SQLException {
		String target = request.getString("target");
		Executor executor = this.map.get(target.toUpperCase());
		
		if (executor == null) {
			throw new JSONException("Target is not found.");
		} else {
			executor.execute(response, request, session, connection);
			
			try (PreparedStatement pstmt = connection.prepareStatement("INSERT INTO"+
				" t_audit values (?, 'add', ?, ?);")) {
				pstmt.setString(1, session.getString("id"));
				pstmt.setString(2, target);
				pstmt.setLong(3, System.currentTimeMillis());
				
				pstmt.executeUpdate();
			}
		}
	}
	
}
