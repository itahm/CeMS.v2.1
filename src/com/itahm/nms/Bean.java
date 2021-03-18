package com.itahm.nms;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Calendar;

import com.itahm.json.JSONObject;

public class Bean {
	public static class Value {
		public long timestamp = Calendar.getInstance().getTimeInMillis();
		public String value = "";
		public int limit = 0;
		public boolean critical = false;
		
		protected void put(long timestamp, String value) {
			this.timestamp = timestamp;
			this.value = value;
		}
		
		public Value set(long timestamp, String value) {
			put(timestamp, value);
			
			return this;
		}
	}
	
	public static class Rollable extends Value {
		private BigDecimal avg = new BigDecimal(0);
		private long max = 0;
		private long min = 0;
		private int count = 0;
		
		public final long id;
		public final String oid;
		public final String index;
		
		public Rollable(long id, String oid, String index) {
			this.id = id;
			this.oid = oid;
			this.index = index;
		}
	
		@Override
		public Value set(long timestamp, String value) {
			super.put(timestamp, value);
			
			try {
				set(Long.valueOf(value));
			} catch (NumberFormatException nfe) {}
			
			return this;
		}
		
		protected void set(long value) {
			if (this.count == 0) {
				this.avg = new BigDecimal(this.min = this.max = value);
			} else {
				this.max = Math.max(this.max, value);
				this.min = Math.min(this.min, value);
				this.avg = this.avg.multiply(new BigDecimal(this.count))
					.add(new BigDecimal(value))
					.divide(new BigDecimal(this.count +1), 10, RoundingMode.HALF_EVEN);
			}
			
			this.count++;
		}
		
		public long min() {
			return this.min;
		}
		
		public long avg() {
			return this.avg.longValue();
		}
		
		public long max() {
			return this.max;
		}
		
		public void clear() {
			this.count = 0;
			this.max = 0;
			this.min = 0;
			this.avg = new BigDecimal(0);
		}
	}
	
	public static class Counter extends Rollable {
		private Long counter;
		private long old;
		private Long before;
		
		public Counter(long id, String oid, String index) {
			super(id, oid, index);
		}
		
		@Override
		public Value set(long timestamp, String value) {
			super.put(timestamp, value);
			
			if (this.before != null && timestamp != this.before) {
				long diff = Long.valueOf(value) - this.old;
				
				if (diff >= 0) {
					this.counter = new BigDecimal(diff)
						.multiply(new BigDecimal(1000))
						.divide(new BigDecimal(timestamp - this.before), RoundingMode.HALF_UP)
						.longValue();
					
					super.set(this.counter);
				}
			}
			
			this.before = timestamp;
			this.old = Long.valueOf(value);
			
			return this;
		}
		
		public Long counter() {
			return this.counter;
		}
	}
	
	public static class Max {
		public final long id;
		public final String index;
		public final long value;
		public final long rate;
		
		public Max (long id, String index, long value) {
			this(id,  index,  value, -1);
		}
		
		public Max (long id, String index, long value, long rate) {
			this.id = id;
			this.index = index;
			this.value = value;
			this.rate = rate;
		}
	}
	
	public static class Rule {
		enum Rolling {
			OTHER, GAUGE, COUNTER
		};
		
		public final static byte OTHER = 0;
		public final static byte GAUGE = 1;
		public final static byte COUNTER = 2;
		
		public final String oid;
		public final String name;
		public final String syntax;
		public final Rolling rolling;
		//public final boolean onChange;
		
		public Rule(String oid, String name, String syntax) {
			this(oid, name, syntax, Rolling.OTHER/*, false*/);
		}
		/*
		public Rule(String oid, String name, String syntax, boolean onChange) {
			this(oid, name, syntax, Rolling.OTHER, onChange);
		}
		
		public Rule(String oid, String name, String syntax, Rolling rolling) {
			this(oid, name, syntax, rolling, false);
		}
		*/
		public Rule(String oid, String name, String syntax, Rolling rolling/*, boolean onChange*/) {
			this.oid = oid;
			this.name = name;
			this.syntax = syntax;
			this.rolling = rolling;
			//this.onChange = onChange;
		}
	}
	
	public static class CriticalEvent extends Event {
		public final String index;
		public final String oid;
		public final boolean critical;
		
		public CriticalEvent(long id, String index, String oid, boolean critical, String title) {
			super(Event.CRITICAL, id, critical? Event.WARNING: Event.NORMAL, String.format("%s 임계 %s", title, critical? "초과": "정상"));
			
			this.index = index;
			this.oid = oid;
			this.critical = critical;
		}
	}
	
	public static class Event {
		public static final String STATUS = "status";
		public static final String SNMP = "snmp";
		public static final String REGISTER = "register";
		public static final String SEARCH = "search";
		public static final String CRITICAL = "critical";
		public static final String IFMON = "ifmon";
		//public static final String SYSTEM = "system";
		//public static final String CHANGE = "change";
		
		public static final int NORMAL = 0;
		public static final int WARNING = 1;
		public static final int ERROR = 2;
		
		public final String origin;
		public final long id;
		public final int level;
		public String message;
		
		public Event(String origin, long id, int level, String message) {
			this.origin = origin;
			this.id = id;
			this.level = level;
			this.message = message;
		}
		
		public JSONObject getJSONObject() {
			return new JSONObject()
				.put("origin", this.origin)
				.put("id", this.id)
				.put("level", this.level)
				.put("message", this.message);
		}
	}
	
	
	public static class Config {
		public long requestInterval = 10000L;
		public int timeout = 5000;
		public int retry = 2;
		public long saveInterval = 60000L *5;
		public long storeDate = 0L;
		public boolean smtpEnable = false;
		public boolean ifMon = false;
		public String smtpServer;
		public String smtpProtocol;
		public String smtpUser;
		public String smtpPassword;
		public String syslog;
		
		public JSONObject getJSONObject() {
			JSONObject config = new JSONObject();
			
			config
				.put("requestInterval", this.requestInterval)
				.put("timeout", this.timeout)
				.put("retry", this.retry)
				.put("saveInterval", this.saveInterval)
				.put("storeDate", this.storeDate)
				.put("smtpEnable", this.smtpEnable)
				.put("ifMon", ifMon);
			
			if (this.smtpServer != null) {
				config.put("smtpServer", this.smtpServer);
			}
			
			if (this.smtpProtocol != null) {
				config.put("smtpProtocol", this.smtpProtocol);
			}
			
			if (this.smtpUser != null) {
				config.put("smtpUser", this.smtpUser);
			}
			
			if (this.smtpPassword != null) {
				config.put("smtpPassword", this.smtpPassword);
			}
			
			if (this.syslog != null) {
				config.put("syslog", this.syslog);
			}
			
			return config;
		}
	}
	
	public static class Profile {
		public final String name;
		public final int version;
		public final String security;
		public final int port;
		public final int level;
		
		public Profile (String name, int port, int version, String security) {
			this(name, version, port, security, 0);
			
		}
		
		public Profile (String name, int port, int version, String security, int level) {
			this.name = name;
			this.version = version;
			this.port = port;
			this.security = security;
			this.level = level;
		}
	}
}