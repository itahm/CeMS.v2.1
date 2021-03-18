package com.itahm.nms;

import java.io.Closeable;
import java.nio.file.Path;
import java.sql.SQLException;

import com.itahm.json.JSONObject;
import com.itahm.nms.Bean.Event;

public interface Commander extends Closeable {
	public boolean addBody(JSONObject body);
	public boolean addBranch(JSONObject branch);
	public boolean addFacility(JSONObject facility) throws SQLException;
	public JSONObject addIcon(String type, JSONObject icon);
	public boolean addLink(long path);
	public JSONObject addNode(JSONObject node);
	public boolean addPath(long nodeFrom, long nodeTo);
	public boolean addProfile(String name, JSONObject profile);
	public boolean addRack(JSONObject rack);
	public boolean addUser(String id, JSONObject user) throws SQLException;
	public void backup() throws Exception;
	public JSONObject getBranch();
	public JSONObject getBranch(long id) throws SQLException;
	public JSONObject getBody() throws SQLException;
	public JSONObject getBody(long id) throws SQLException;
	public JSONObject getConfig();
	public JSONObject getEvent(JSONObject search) throws SQLException;
	public JSONObject getEvent(long eventID) throws SQLException;
	public JSONObject getEventByDate(long date) throws SQLException;
	public JSONObject getFacility(long id) throws SQLException;
	public JSONObject getFacility() throws SQLException;
	public JSONObject getIcon() throws SQLException;
	public JSONObject getIcon(String type) throws SQLException;
	public JSONObject getInformation();
	public JSONObject getLimit() throws SQLException;
	public JSONObject getLimit(long id, String index, String oid);
	public JSONObject getLink() throws SQLException;
	public JSONObject getLink(long path) throws SQLException;
	public JSONObject getLocation() throws SQLException;
	public JSONObject getLocation(long node) throws SQLException;
	public JSONObject getManager(long node) throws SQLException;
	public JSONObject getNode(long id, boolean snmp) throws SQLException;
	public JSONObject getNode(String filter) throws SQLException;
	public JSONObject getPath() throws SQLException;
	public JSONObject getPath(long nodeFrom, long nodeTo) throws SQLException;
	public JSONObject getPosition(String name) throws SQLException;
	public JSONObject getProfile() throws SQLException;
	public JSONObject getProfile(String name) throws SQLException;
	public JSONObject getRack() throws SQLException;
	public JSONObject getRack(int id) throws SQLException;
	public JSONObject getResource(long id, String oid, String index, long date);
	public JSONObject getResource(long id, String oid, String index);
	public JSONObject getResource(long id, String oid, String index, long from, long to);
	public Path getRoot();
	public JSONObject getSetting() throws SQLException;
	public JSONObject getSetting(String key) throws SQLException;
	public JSONObject getTop(int count);
	public JSONObject getTraffic(JSONObject traffic);
	public JSONObject getUser(boolean event) throws SQLException;
	public JSONObject getUser(String id) throws SQLException;
	public boolean search(String network, int mask, String profile) throws SQLException;
	public void sendEvent (Event event);
	public void setAuth(String id, JSONObject auth) throws SQLException;
	public void setBandwidth(long id, String index, String value) throws SQLException;
	public void setBranch(long id, JSONObject branch) throws SQLException;
	public boolean setBody(long id, JSONObject body);
	public boolean setFacility(long id, JSONObject facility) throws SQLException;
	public void setLimit(long id, String oid, String index, int limit) throws SQLException;
	public void setIcon(String id, JSONObject icon) throws SQLException;
	public void setIFMon(boolean enable) throws SQLException;
	public void setLink(JSONObject link) throws SQLException;
	public boolean setLocation(long node, JSONObject location) throws SQLException;
	public void setManager(long node, String user) throws SQLException;
	public void setMonitor(long id, String ip, String protocol) throws SQLException;
	public void setNode(long id, JSONObject node) throws SQLException;
	public void setPassword(String id, String password) throws SQLException;
	public void setPath(JSONObject path) throws SQLException;
	public void setPosition(String name, JSONObject position) throws SQLException;
	public void setRetry(int retry) throws SQLException;
	public void setRack(JSONObject rack) throws SQLException;
	public void setRack(int id, JSONObject rack) throws SQLException;
	public void setRequestInterval(long interval) throws SQLException;
	public void setSaveInterval(int interval) throws SQLException;
	public void setSetting(String key, String value) throws SQLException;
	public boolean setSMTP(JSONObject smtp);
	public void setStoreDate(int period) throws SQLException;
	public boolean setSyslog(String address);
	public void setTimeout(int timeout) throws SQLException;
	public void setUser(String id, JSONObject user) throws SQLException;
	public JSONObject signIn(String id, String password) throws SQLException;
	public void start();
	public void removeBandwidth(long id, String index) throws SQLException;
	public boolean removeBranch(long id);
	public boolean removeBody(long id);
	public boolean removeFacility(long id) throws SQLException;
	public boolean removeIcon(String type);
	public boolean removeLink(long id);
	public boolean removeLocation(long node);
	public boolean removeNode(long id);
	public boolean removePath(long id);
	public boolean removeProfile(String name);
	public boolean removeRack(int id);
	public void removeUser(String id) throws SQLException;
	public void test(Object... args);
}