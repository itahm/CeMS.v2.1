package com.itahm.http;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

public class Connection implements Closeable {

	public enum Header {
		ORIGIN, SESSION;
	};
	
	public final static long TIMEOUT_HOUR = 60 *60 *1000;
	public final static byte CR = (byte)'\r';
	public final static byte LF = (byte)'\n';
	public final static String GET = "GET";
	public final static String POST = "POST";
	public final static String HEAD = "HEAD";
	public final static String OPTIONS = "OPTIONS";
	public final static String DELETE = "DELETE";
	public final static String TRACE = "TRACE";
	public final static String CONNECT = "CONNECT";

	private final static Timer timer = new Timer("ITAhM Connection timer", true);
	
	private Map<String, String> header = new HashMap<>();
	
	private final SocketChannel channel;
	private final HTTPServer listener;
	private byte [] buffer;
	private TimerTask task;
	private int length;
	private String startLine;
	private ByteArrayOutputStream body;
	private boolean initialized = true;
	private Boolean closed = false;
	
	public Connection(SocketChannel channel, HTTPServer listener) {
		this.channel = channel;
		this.listener = listener;
		
		setTimeout();
	}
	
	public void parse(ByteBuffer src) throws IOException {
		setTimeout();
		
		if (this.body == null) {
			String line;
			
			while ((line = readLine(src)) != null) {
				if (parseHeader(line)) {
					src.compact().flip();
					
					parseBody(src);
					
					break;
				};
			}
		}
		else {
			parseBody(src);
		}
	}
	
	private void setTimeout() {
		final Connection request = this;
		
		if (this.task != null) {
			this.task.cancel();
		}
		
		this.task = new TimerTask() {

			@Override
			public void run() {
				try {
					listener.closeRequest(request);
				} catch (IOException ioe) {
					ioe.printStackTrace();
				}
			}
		};
		
		timer.schedule(this.task, TIMEOUT_HOUR);
	}
	
	private void parseBody(ByteBuffer src) throws IOException {
		byte [] bytes = new byte[src.limit()];
		int length;
		
		src.get(bytes);
		this.body.write(bytes);
		
		length = this.body.size();
		if (this.length == length) {
			new HTTPProcessor(this.listener, this);
			
			this.body = null;
			this.initialized = true;
		}
		else if (this.length < length){
			throw new IOException("malformed http request");
		}
		
	}
	
	private boolean parseHeader(String line) throws IOException {
		if (this.initialized) {
			if (line.length() != 0) {
				this.startLine = line;
				this.header = new HashMap<>();
				
				this.initialized = false;	
			}
			//else ????????? ?????? request-line ????????? ??? ????????? ????????????.
		}
		else {
			if ("".equals(line)) {			
				String length = this.header.get("content-length");
				
				try {
					this.length = Integer.parseInt(length);
				} catch (NumberFormatException nfe) {
					this.length = 0;
				}
				
				this.body = new ByteArrayOutputStream();
				
				return true;
			}
			else {
				int index = line.indexOf(":");
				
				if (index == -1) {
					throw new IOException("malformed http request");
				}
				
				this.header.put(line.substring(0, index).toLowerCase(), line.substring(index + 1).trim());
			}
		}
		
		return false;
	}
	
	private String readLine(ByteBuffer src) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		if (this.buffer != null) {
			baos.write(this.buffer);
			
			this.buffer = null;
		}
		
		int b;
		
		while(src.hasRemaining()) {
			b = src.get();
			baos.write(b);
			
			if (b == LF) {
				String line = readLine(baos.toByteArray());
				if (line != null) {
					return line;
				}
			}
		}
		
		this.buffer = baos.toByteArray();
		
		return null;
	}
	
	public static String readLine(byte [] src) throws IOException {
		int length = src.length;
		
		if (length > 1 && src[length - 2] == CR) {
			return new String(src, 0, length -2);
		}
		
		return null;
	}

	public boolean isClosed() {
		synchronized(closed) {
			return closed;
		}
	}
	
	public Map<String, String> getHeader() {
		return this.header;
	}
	
	public HTTPRequest createRequest() {
		try {			
			return new HTTPRequest(this.channel.getRemoteAddress(), this.startLine, this.header, this.body.toByteArray());
		} catch (IOException ioe) {
			ioe.printStackTrace();
			
			return null;
		}
	}
	
	public boolean write(HTTPResponse response) throws IOException {
		synchronized(closed) {
			if (closed) {
				return false;
			}
			
			ByteBuffer message = response.build();
			
			while(message.remaining() > 0) {			
				this.channel.write(message);
			}
		}
		
		return true;
	}
	
	@Override
	public void close() throws IOException {
		synchronized(closed) {
			if (closed) {
				return;
			}
			
			closed = true;
		}

		try {
			this.channel.close();
		}
		finally {
			if (this.task != null) {
				this.task.cancel();
			}
		}
	}
}
