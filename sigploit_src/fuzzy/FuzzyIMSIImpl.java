/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2012, Telestax Inc and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package fuzzy;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.ss7.map.api.MAPException;
import org.mobicents.protocols.ss7.map.api.MAPParsingComponentException;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class FuzzyIMSIImpl extends FuzzyTbcdString implements FuzzyIMSI {

    private static final String NUMBER = "number";

    public FuzzyIMSIImpl() {
	super(1, 8, "IMSI");
    }

    public FuzzyIMSIImpl(String data) {
	super(3, 8, "IMSI", data);
    }

    public String getData() {
	return this.data;
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<FuzzyIMSIImpl> IMSI_XML = new XMLFormat<FuzzyIMSIImpl>(FuzzyIMSIImpl.class) {

	@Override
	public void read(XMLFormat.InputElement xml, FuzzyIMSIImpl imsi) throws XMLStreamException {
	    imsi.data = xml.getAttribute(NUMBER, "");
	}

	@Override
	public void write(FuzzyIMSIImpl imsi, javolution.xml.XMLFormat.OutputElement xml) throws XMLStreamException {
	    xml.setAttribute(NUMBER, imsi.data);
	}
    };

    @Override
    public void decodeAll(AsnInputStream arg0) throws MAPParsingComponentException {
	// TODO Auto-generated method stub

    }

    @Override
    public void decodeData(AsnInputStream arg0, int arg1) throws MAPParsingComponentException {
	// TODO Auto-generated method stub

    }

    @Override
    public void encodeAll(AsnOutputStream arg0) throws MAPException {
	// TODO Auto-generated method stub

    }

    @Override
    public void encodeAll(AsnOutputStream arg0, int arg1, int arg2) throws MAPException {
	// TODO Auto-generated method stub

    }

    @Override
    public void encodeData(AsnOutputStream arg0) throws MAPException {
	// TODO Auto-generated method stub

    }
}
